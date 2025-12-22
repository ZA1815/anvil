use std::ffi::c_void;
use std::io::{Error, ErrorKind};
use std::ptr::copy_nonoverlapping;

use windows::Win32::System::Hypervisor::{
    WHV_PARTITION_HANDLE,
    WHvCreatePartition,
    WHvCreateVirtualProcessor,
    WHvMapGpaRange,
    WHvMapGpaRangeFlagExecute,
    WHvMapGpaRangeFlagRead,
    WHvMapGpaRangeFlagWrite,
    WHvPartitionPropertyCodeProcessorCount,
    WHvSetPartitionProperty,
    WHvSetupPartition
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
        
    }
    
    fn run(&mut self) -> ExitReason {
        
    }
}