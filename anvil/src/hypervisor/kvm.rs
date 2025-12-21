use std::io::{self, Error};
use std::os::fd::FromRawFd;
use std::os::unix::io::{AsRawFd};
use std::mem::ManuallyDrop;
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

// vCPU magic numbers
const KVM_GET_REGS: u64 = 0x8090ae81;
const KVM_SET_REGS: u64 = 0x4090ae82;
const KVM_GET_SREGS: u64 = 0x8138ae83;
const KVM_SET_SREGS: u64 = 0x4138ae84;

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
pub union KvmRunUnion {
    pub io: ManuallyDrop<KvmIo>,
    pub fail_entry: ManuallyDrop<KvmFailEntry>,
    pub internal_error: ManuallyDrop<KvmInternalError>,
    pub _padding: [u8; 256]
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmIo {
    pub direction: u8,
    pub size: u8,
    pub port: u16,
    pub count: u32,
    pub data_offset: u64
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmFailEntry {
    pub hardware_entry_failure_reason: u64,
    pub cpu: u32
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmInternalError {
    pub suberror: u32,
    pub ndata: u32,
    pub data: [u64; 16]
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmSegment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmDtable {
    pub base: u64,
    pub limit: u16,
    pub _padding: [u16; 3]
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmSregs {
    pub cs: KvmSegment,
    pub ds: KvmSegment,
    pub es: KvmSegment,
    pub fs: KvmSegment,
    pub gs: KvmSegment,
    pub ss: KvmSegment,
    pub tr: KvmSegment,
    pub ldt: KvmSegment,
    pub gdt: KvmSegment,
    pub idt: KvmSegment,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4]
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
        let end_addr = guest_addr.checked_add(data.len() as u64).ok_or(Error::new(io::ErrorKind::Other, "Address overflow"))?;
        if self.guest_mem_size <  end_addr as usize {
            return Err(Error::new(io::ErrorKind::Other, "Guest memory underallocated"));
        }
        
        let start = self.guest_mem as u64 + guest_addr;
        
        unsafe { copy_nonoverlapping(data.as_ptr(), start as *mut u8, data.len()) };
        
        Ok(())
    }
    
    fn set_entry_point(&mut self, addr: u64) -> io::Result<()> {
        let mut regs = KvmRegs::default();
        let mut sregs = KvmSregs::default();
        
        let get_regs = unsafe { ioctl(self.vcpu_handle.as_raw_fd(), KVM_GET_REGS, &mut regs) };
        if get_regs == -1 {
            return Err(Error::last_os_error());
        }
        regs.rip = addr;
        regs.rflags = 0x2;
        
        let get_sregs = unsafe { ioctl(self.vcpu_handle.as_raw_fd(), KVM_GET_SREGS, &mut sregs) };
        if get_sregs == -1 {
            return Err(Error::last_os_error());
        }
        sregs.cs.base = 0;
        sregs.cs.selector = 0;
        sregs.cs.l = 0; // Change back later, test first in 16-bit then switch back to long mode
        
        let set_regs = unsafe { ioctl(self.vcpu_handle.as_raw_fd(), KVM_SET_REGS, &regs) };
        if set_regs == -1 {
            return Err(Error::last_os_error());
        }
        
        let set_sregs = unsafe { ioctl(self.vcpu_handle.as_raw_fd(), KVM_SET_SREGS, &sregs) };
        if set_sregs == -1 {
            return Err(Error::last_os_error());
        }
    
        Ok(())
    }
    
    fn run(&mut self) -> ExitReason {
        let run = unsafe { ioctl(self.vcpu_handle.as_raw_fd(), KVM_RUN) };
        if run == -1 {
            return ExitReason::Error("System-level Error, VM did not pause successfully".to_string());
        }
        
        
        unsafe  {
            match (*self.run_info).exit_reason as u64 {
                KVM_EXIT_IO => {
                    let io = &(*self.run_info).union.io;
                    match io.direction {
                        0 => ExitReason::IoIn { port: io.port, size: io.count as usize },
                        1 => {
                            let total_len = match (io.count).checked_mul(io.size as u32) {
                                Some(val) => val,
                                None => return ExitReason::Error("Total len out of bounds".to_string())
                            };
                            
                            let end_offset = match io.data_offset.checked_add(total_len as u64) {
                                Some(val) => val,
                                None => return ExitReason::Error("Kernel offset overflow".to_string())
                            };
                            if end_offset as usize > self.run_size {
                                return ExitReason::Error("Kernel offset out of bounds".to_string());
                            }
                            
                            let data_ptr = (self.run_info as *const u8).add(io.data_offset as usize);
                            
                            let data_slice = slice_from_raw_parts(data_ptr, total_len as usize);
                            let data_vec = (*data_slice).to_vec();
                            
                            ExitReason::IoOut { port: io.port, data: data_vec }
                        },
                        _ => ExitReason::Error("Unknown direction".to_string())
                    }
                },
                KVM_EXIT_DEBUG => ExitReason::DebugPoint,
                KVM_EXIT_HLT => ExitReason::Halt,
                KVM_EXIT_SHUTDOWN => ExitReason::Shutdown,
                KVM_EXIT_FAIL_ENTRY => {
                    let fe = &(*self.run_info).union.fail_entry;
                    ExitReason::FailEntry { hardware_reason: fe.hardware_entry_failure_reason, cpu: fe.cpu }
                },
                KVM_EXIT_INTERNAL_ERROR => {
                    let ie = &(*self.run_info).union.internal_error;
                    ExitReason::InternalError { suberror: ie.suberror, data: ie.data.to_vec() }
                },
                _ => ExitReason::Error("Unknown error".to_string())
            }
        }
    }
}