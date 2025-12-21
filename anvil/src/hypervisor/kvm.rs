use std::io::{self, Error};
use std::os::fd::FromRawFd;
use std::os::unix::io::{AsRawFd};

use std::fs::File;
use std::ptr::{copy_nonoverlapping, null_mut, slice_from_raw_parts};
use libc::{MAP_ANONYMOUS, MAP_PRIVATE, MAP_SHARED, PROT_READ, PROT_WRITE, c_void, ioctl, mmap, munmap};

use crate::hypervisor::{ExitReason, Hypervisor};

// VM creation magic numbers
const KVM_CREATE_VM: u64 = 0xae01;
const KVM_SET_USER_MEMORY_REGION: u64 = 0x4020ae46;
const KVM_CREATE_VCPU: u64 = 0xae41;
const KVM_GET_VCPU_MMAP_SIZE: u64 = 0xae04;

// VM run magic numbers
const KVM_RUN: u64 = 0xae80;
const KVM_EXIT_IO: u64 = 2;
const KVM_EXIT_DEBUG: u64 = 4;
const KVM_EXIT_HLT: u64 = 5;
const KVM_EXIT_SHUTDOWN: u64 = 8;
const KVM_EXIT_FAIL_ENTRY: u64 = 9;
const KVM_EXIT_INTERNAL_ERROR: u64 = 17;

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
    
    pub union: KvmRunUnion
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
    fn create_vm(memory_mb: usize) -> io::Result<Self> where Self: Sized {
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
    
    fn load_binary(&mut self, data: &[u8], guest_addr: u64) -> io::Result<()> {
        if self.guest_mem_size < data.len() + guest_addr as usize {
            return Err(Error::new(io::ErrorKind::Other, "Guest memory underallocated"));
        }
        
        let start = self.guest_mem as u64 + guest_addr;
        
        unsafe { copy_nonoverlapping(data.as_ptr(), start as *mut u8, data.len()) };
        
        Ok(())
    }
    
    fn run(&mut self) -> ExitReason {
        let run = unsafe { ioctl(self.vcpu_handle.as_raw_fd(), KVM_RUN) };
        if run == -1 {
            return ExitReason::Error("System-level Error, VM did not pause successfully".to_string());
        }
        
        let io = unsafe { &(*self.run_info).union.io };
        
        unsafe  {
            match (*self.run_info).exit_reason as u64 {
                KVM_EXIT_IO => match io.direction {
                    0 => ExitReason::IoIn { port: io.port, size: io.count as usize },
                    1 => {
                        let data_ptr = (self.run_info as *const u8).add(io.data_offset as usize);
                        
                        let data_slice = slice_from_raw_parts(data_ptr, (io.count * io.size as u32) as usize);
                        let data_vec = (*data_slice).to_vec();
                        
                        ExitReason::IoOut { port: io.port, data: data_vec }
                    },
                    _ => ExitReason::Error("Unknown direction".to_string())
                },
                KVM_EXIT_DEBUG => ExitReason::DebugPoint,
                KVM_EXIT_HLT => ExitReason::Halt,
                KVM_EXIT_SHUTDOWN => ExitReason::Shutdown,
                KVM_EXIT_FAIL_ENTRY => ExitReason::FailEntry,
                KVM_EXIT_INTERNAL_ERROR => ExitReason::InternalError,
                _ => ExitReason::Error("Unknown error".to_string())
            }
        }
    }
}