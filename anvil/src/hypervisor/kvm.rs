use std::io::{self, Error};
use std::os::fd::FromRawFd;
use std::os::unix::io::{AsRawFd};

use std::fs::File;
use std::ptr::{copy_nonoverlapping, null_mut};
use libc::{MAP_ANONYMOUS, MAP_PRIVATE, MAP_SHARED, PROT_READ, PROT_WRITE, c_void, ioctl, memcpy, mmap, munmap};

use crate::hypervisor::Hypervisor;

const KVM_CREATE_VM: u64 = 0xae01;
const KVM_SET_USER_MEMORY_REGION: u64 = 0x4020ae46;
const KVM_CREATE_VCPU: u64 = 0xae41;
const KVM_GET_VCPU_MMAP_SIZE: u64 = 0xae04;

pub struct KvmVm {
    pub kvm_handle: File,
    pub vm_handle: File,
    pub vcpu_handle: File,
    pub guest_mem: *mut c_void,
    pub guest_mem_size: usize,
    pub run_info: *mut KvmRun,
    pub run_size: usize
}

#[repr(C)]
struct KvmUserspaceMemoryRegion {
    pub slot: u32,
    pub flags: u32,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64
}

#[repr(C)]
pub struct KvmRun {
    pub exit_reason: u32,
    pub ready_for_interrupt_injection: u8,
    pub if_flag: u8,
    pub flags: u16,
    pub cr8: u64,
    pub apic_base: u64,
    
    pub u: KvmRunUnion
}

#[repr(C)]
pub struct KvmRunUnion {
    pub io: KvmIo,
    pub _padding: [u8; 256]
}

#[repr(C)]
pub struct KvmIo {
    pub direction: u8,
    pub size: u8,
    pub port: u16,
    pub count: u32,
    pub data_offset: u64
}

impl Drop for KvmVm {
    fn drop(&mut self) {
        unsafe {
            munmap(self.run_info as *mut c_void, self.run_size);
            munmap(self.guest_mem, self.guest_mem_size);
        }
    }
}

impl Hypervisor for KvmVm {
    fn create_vm(memory_mb: usize) -> std::io::Result<Self> where Self: Sized {
        // Open KVM file (which tells the kernel that we want to use KVM)
        let kvm = File::open("/dev/kvm")?;
        let kvm_fd = kvm.as_raw_fd();
        
        // Use ioctl and the create VM magic number to tell KVM to create a VM
        let vm_fd = unsafe {
            ioctl(kvm_fd, KVM_CREATE_VM, 0)
        };
        let vm = unsafe { File::from_raw_fd(vm_fd) };
        
        // Convert the MBs into bytes and mmap the host memory by giving read/write perms and not associating it with a specific file
        let mem_size = memory_mb * 1024 * 1024;
        let mem = unsafe {
            mmap(null_mut(), mem_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
        };
        
        // Struct to tell KVM how to access the new mmap'd memory
        let region = KvmUserspaceMemoryRegion {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: mem_size as u64,
            userspace_addr: mem as u64,
            flags: 0
        };
        // Use ioctl to pass in the host memory struct and associate it with the VM
        unsafe {
            ioctl(vm.as_raw_fd(), KVM_SET_USER_MEMORY_REGION, &region);
        }
        
        // Use ioctl and the create vCPU magic number to tell KVM to add a single vCPU to the VM
        let vcpu_fd = unsafe {
            ioctl(vm.as_raw_fd(), KVM_CREATE_VCPU, 0)
        };
        let vcpu = unsafe { File::from_raw_fd(vcpu_fd) };
        
        // Use ioctl and tell KVM how large the run data will be
        let run_size = unsafe {
            ioctl(vcpu.as_raw_fd(), KVM_GET_VCPU_MMAP_SIZE, 0)
        };
        // Actually mmap the run data
        let run = unsafe {
            mmap(null_mut(), run_size as usize, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu.as_raw_fd(), 0) as *mut KvmRun
        };
        
        Ok(KvmVm {
            kvm_handle: kvm,
            vm_handle: vm,
            vcpu_handle: vcpu,
            guest_mem: mem,
            guest_mem_size: mem_size,
            run_info: run,
            run_size: run_size as usize
        })
    }
    
    fn load_binary(&mut self, data: &[u8], guest_addr: u64) -> std::io::Result<()> {
        if self.guest_mem_size < data.len() + guest_addr as usize {
            return Err(Error::new(io::ErrorKind::Other, "Guest memory underallocated"));
        }
        
        let start = self.guest_mem as u64 + guest_addr;
        
        unsafe { copy_nonoverlapping(data.as_ptr(), start as *mut u8, data.len()) };
        
        Ok(())
    }
}