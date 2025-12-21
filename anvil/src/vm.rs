use anyhow::Ok;

use crate::hypervisor::{ExitReason, Hypervisor, PlatformHypervisor};

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
    pub fn create_vm(memory_mb: usize) -> anyhow::Result<Self> {
        let hypervisor = PlatformHypervisor::create_vm(memory_mb)?;
        
        Ok(Self { hypervisor })
    }
    
    pub fn load_binary(&mut self, data: &[u8], guest_addr: u64) -> anyhow::Result<()> {
        self.hypervisor.load_binary(data, guest_addr)?;
        
        Ok(())
    }
    
    pub fn set_entry_point(&mut self, addr: u64) -> anyhow::Result<()> {
        self.hypervisor.set_entry_point(addr)?;
        
        Ok(())
    }
    
    pub fn run(&mut self) -> VmExitReason {
        let exit_reason = loop {
            match self.hypervisor.run() {
                ExitReason::Halt => {
                    break VmExitReason::Halt;
                },
                ExitReason::IoIn { port, size } => {
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
                        
                    };
                    VmExitReason::FailEntry(error_string);
                },
                ExitReason::InternalError { suberror, data } => {
                    let error_string = match suberror {
                        
                    };
                    VmExitReason::InternalError(error_string);
                },
                ExitReason::Error(reason) => VmExitReason::Error(reason),
                ExitReason::DebugPoint => {
                    continue;
                }
            };
        };
        
        exit_reason
    }
}