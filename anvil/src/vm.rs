use std::sync::{atomic::AtomicBool, mpsc::Sender};
use std::sync::Arc;
use std::io::Result;

use crate::hypervisor::{CancelToken, CpuMode, ExitReason, GuestInfo, Hypervisor, PlatformHypervisor, Register};

pub struct AnvilVm {
    hypervisor: PlatformHypervisor
}

pub enum VmExitReason {
    // Successes
    Halt,
    Shutdown,
    // Failures
    FailEntry(String),
    InternalError(String),
    Error(String)
}

impl AnvilVm {
    pub fn create_vm(memory_mb: usize) -> anyhow::Result<(Self, Arc<AtomicBool>, Arc<AtomicBool>)> {
        let hypervisor = PlatformHypervisor::create_vm(memory_mb)?;
        let stop_flag = hypervisor.stop_flag.clone();
        let early_end_flag = hypervisor.early_end_flag.clone();
        
        Ok((Self { hypervisor }, stop_flag, early_end_flag))
    }
    
    pub fn setup_reqs(&mut self, memory_mb: usize, guest_gdt_addr: u64, cpu_mode: CpuMode) -> Result<()> {
        self.hypervisor.setup_pts(memory_mb, cpu_mode);
        self.hypervisor.setup_tss(cpu_mode)?;
        self.hypervisor.setup_gdt(guest_gdt_addr, cpu_mode);
        
        Ok(())
    }
    
    pub fn load_binary(&mut self, data: &[u8], guest_addr: u64) -> anyhow::Result<()> {
        self.hypervisor.load_binary(data, guest_addr)?;
        
        Ok(())
    }
    
    pub fn set_entry_point(&mut self, mem_reg: Register, exec_addr: u64, guest_info: Option<GuestInfo>, cpu_mode: CpuMode) -> anyhow::Result<()> {
        self.hypervisor.set_entry_point(mem_reg, exec_addr, guest_info, cpu_mode)?;
        
        Ok(())
    }
    
    pub fn run(&mut self, tx: &Sender<CancelToken>) -> VmExitReason {
        let exit_reason = loop {
            match self.hypervisor.run(&tx) {
                ExitReason::Halt => {
                    break VmExitReason::Halt;
                },
                ExitReason::IoIn { .. } => {
                    // Still have to implement this Hypervisor.framework
                    continue;
                },
                ExitReason::IoOut { port, data } => {
                    if port == 0x3F8 {
                        print!("{}", String::from_utf8_lossy(&data));
                    }
                    continue;
                },
                ExitReason::Shutdown => {
                    break VmExitReason::Shutdown;
                },
                ExitReason::FailEntry { hardware_reason, cpu } => {
                    let error_string = match hardware_reason {
                        1 => "VMCALL executed in VMX root operation".to_string(),
                        2 => "VMCLEAR with invalid physical address".to_string(),
                        3 => "VMCLEAR with VMXON pointer".to_string(),
                        4 => "VMLAUNCH with non-clear VMCS".to_string(),
                        5 => "VMRESUME with non-launched VMCS".to_string(),
                        6 => "VMRESUME after VMXOFF".to_string(),
                        7 => "VM entry with invalid control field(s)".to_string(),
                        8 => "VM entry with invalid host-state field(s)".to_string(),
                        9 => "VMPTRLD with invalid physical address".to_string(),
                        10 => "VMPTRLD with VMXON pointer".to_string(),
                        11 => "VMPTRLD with incorrect VMCS revision identifier".to_string(),
                        12 => "VMREAD/VMWRITE from/to unsupported VMCS component".to_string(),
                        13 => "VMWRITE to read-only VMCS component".to_string(),
                        2147483681 => "VM-entry failure due to invalid guest state".to_string(),
                        2147483682 => "VM-entry failure due to MSR loading".to_string(),
                        2147483689 => "VM-entry failure due to machine-check event".to_string(),
                        _ => format!("Unknown Hardware Error: {:#x}", hardware_reason),
                    };
                    break VmExitReason::FailEntry(format!("FailEntry error: '{}' on vCPU: {}", error_string, cpu));
                },
                ExitReason::InternalError { suberror, data } => {
                    let error_string = match suberror {
                        1 => "KVM_INTERNAL_ERROR_EMULATION".to_string(),
                        2 => "KVM_INTERNAL_ERROR_SIMUL_EX".to_string(),
                        3 => "KVM_INTERNAL_ERROR_DELIVERY_EV".to_string(),
                        4 => "KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON".to_string(),
                        _ => format!("Unknown Internal Error: {}", suberror),
                    };
                    break VmExitReason::InternalError(format!("InternalError error: '{}' with data: {:#?}", error_string, data));
                },
                ExitReason::Error(reason) => break VmExitReason::Error(reason),
                ExitReason::DebugPoint => {
                    continue;
                }
            };
        };
        
        exit_reason
    }
}