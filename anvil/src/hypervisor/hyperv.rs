use std::ffi::c_void;
use std::io::{Error, ErrorKind};
use std::mem;
use std::ptr::copy_nonoverlapping;

use windows::Win32::System::Hypervisor::{
    WHV_PARTITION_HANDLE,
    WHV_REGISTER_NAME,
    WHV_REGISTER_VALUE,
    WHV_X64_SEGMENT_REGISTER,
    WHV_X64_SEGMENT_REGISTER_0,
    WHV_RUN_VP_EXIT_CONTEXT,
    WHvCreatePartition,
    WHvCreateVirtualProcessor,
    WHvMapGpaRange,
    WHvMapGpaRangeFlagExecute,
    WHvMapGpaRangeFlagRead,
    WHvMapGpaRangeFlagWrite,
    WHvPartitionPropertyCodeProcessorCount,
    WHvSetPartitionProperty,
    WHvSetupPartition,
    WHvSetVirtualProcessorRegisters,
    WHvX64RegisterRip,
    WHvX64RegisterRflags,
    WHvX64RegisterCs,
    WHvRunVirtualProcessor,
    WHvRunVpExitReasonX64Halt,
    WHvRunVpExitReasonX64IoPortAccess,
    WHvRunVpExitReasonUnrecoverableException,
    WHvRunVpExitReasonInvalidVpRegisterValue
};
use windows::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};

use crate::hypervisor::{ExitReason, Hypervisor};

pub struct HyperVVm {
    pub partition: WHV_PARTITION_HANDLE,
    pub guest_mem: *mut c_void,
    pub guest_mem_size: usize
}

impl Hypervisor for HyperVVm {
    fn create_vm(memory_mb: usize) -> std::io::Result<Self> where Self: Sized {
        let partition = unsafe { WHvCreatePartition()? };
        
        let vcpu_count: u32 = 1;
        unsafe {
            WHvSetPartitionProperty(
                partition,
                WHvPartitionPropertyCodeProcessorCount,
                &vcpu_count as *const _ as *const _,
                size_of::<u32>() as u32
            )?
        };
        
        unsafe { WHvSetupPartition(partition)? };
        
        let guest_mem_size = match memory_mb.checked_mul(1024 * 1024) {
            Some(val) => val,
            None => return Err(Error::new(ErrorKind::Other, "Memory allocated too large for architecture"))
        };
        let guest_mem = unsafe { VirtualAlloc(None, guest_mem_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        unsafe {
            WHvMapGpaRange(
                partition,
                guest_mem,
                0x0000,
                guest_mem_size as u64,
                WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute
            )?
        };
        
        let vcpu_index: u32 = 0;
        unsafe { WHvCreateVirtualProcessor(partition, vcpu_index, 0)? };
        
        Ok(HyperVVm { partition, guest_mem, guest_mem_size })
    }
    
    fn load_binary(&mut self, data: &[u8], guest_addr: u64) -> std::io::Result<()> {
        let end_addr = guest_addr.checked_add(data.len() as u64).ok_or(Error::new(ErrorKind::Other, "Address overflow"))?;
        if self.guest_mem_size < end_addr as usize {
            return Err(Error::new(ErrorKind::Other, "Guest memory underallocated"));
        }
        
        let start = self.guest_mem as u64 + guest_addr;
        
        unsafe { copy_nonoverlapping(data.as_ptr(), start as *mut u8, data.len()) };
        
        Ok(())
    }
    
    fn set_entry_point(&mut self, addr: u64) -> std::io::Result<()> {
        let reg_keys: [WHV_REGISTER_NAME; 3] = [
            WHvX64RegisterRip,
            WHvX64RegisterRflags,
            WHvX64RegisterCs
        ];
        let cs = WHV_X64_SEGMENT_REGISTER {
            Base: 0,
            Limit: 0xFFFF,
            Selector: 0,
            Anonymous: WHV_X64_SEGMENT_REGISTER_0 {
                Attributes: 0x9B
            }
        };
        let reg_values: [WHV_REGISTER_VALUE; 3] = [
            WHV_REGISTER_VALUE { Reg64: addr },
            WHV_REGISTER_VALUE { Reg64: 0x2 },
            WHV_REGISTER_VALUE { Segment: cs }
        ];
        
        unsafe { WHvSetVirtualProcessorRegisters(self.partition, 0, reg_keys.as_ptr(), 3, reg_values.as_ptr())? };
        
        Ok(())
    }
    
    fn run(&mut self) -> ExitReason {
        let mut exit_cx: WHV_RUN_VP_EXIT_CONTEXT = unsafe {  mem::zeroed() };
        let exit_cx_size = mem::size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32;
        
        let run = unsafe { WHvRunVirtualProcessor(self.partition, 0, &mut exit_cx as *mut _ as *mut _, exit_cx_size) };
        
        if let Err(e) = run {
            return ExitReason::Error(format!("WHvRunVirtualProcessor failed {:#?}", e));
        }
        
        #[allow(non_upper_case_globals)]
        unsafe {
            match exit_cx.ExitReason {
                WHvRunVpExitReasonX64Halt => ExitReason::Halt,
                WHvRunVpExitReasonX64IoPortAccess => {
                    let io = exit_cx.Anonymous.IoPortAccess;
                    let port = io.PortNumber;
                    let size = ((io.AccessInfo.Anonymous._bitfield >> 1) & 0b111) as usize;
                    let is_write = (io.AccessInfo.Anonymous._bitfield & 0b1) != 0;
                    
                    if is_write {
                        let data = (io.Rax as u32).to_le_bytes()[..size].to_vec();
                        
                        let rip = exit_cx.VpContext.Rip as usize;
                        let byte = *(self.guest_mem.add(rip) as *const u8);
                        let instruction_len: u64 = match byte {
                            0xEE | 0xEF => 1,
                            0xE6 | 0xE7 => 2,
                            _ => return ExitReason::Error(format!("Unknown IO instruction: {:#x}", byte))
                        };
                        let new_rip = rip as u64 + instruction_len;
                        
                        let rip_key: [WHV_REGISTER_NAME; 1] = [WHvX64RegisterRip];
                        let rip_value: [WHV_REGISTER_VALUE; 1] = [WHV_REGISTER_VALUE { Reg64: new_rip }];
                        if let Err(e) = WHvSetVirtualProcessorRegisters(self.partition, 0, rip_key.as_ptr(), 1, rip_value.as_ptr())
                        {
                            return ExitReason::Error(format!("WHvSetVirtualProcessorRegisters failed {:#?}", e));
                        }
                        
                        ExitReason::IoOut { port, data }
                    }
                    else {
                        ExitReason::IoIn { port, size }
                    }
                },
                WHvRunVpExitReasonUnrecoverableException => ExitReason::Shutdown,
                WHvRunVpExitReasonInvalidVpRegisterValue => ExitReason::FailEntry { hardware_reason: 0, cpu: 0 },
                _ => ExitReason::Error(format!("Unhandled WHP exit {:?}", exit_cx.ExitReason))
            }
        }
    }
}