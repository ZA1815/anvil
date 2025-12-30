use std::io::{self, Error, ErrorKind};
use std::os::fd::FromRawFd;
use std::os::unix::io::{AsRawFd};
use std::mem::ManuallyDrop;
use std::fs::File;
use std::slice::from_raw_parts;
use std::ptr::{copy_nonoverlapping, null_mut, slice_from_raw_parts};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use libc::{EINTR, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, MAP_SHARED, PROT_READ, PROT_WRITE, c_void, ioctl, mmap, munmap};
use errno;

use crate::hypervisor::{CancelToken, CpuMode, ExitReason, GdtEntry, GdtPointer, Hypervisor, Tss32, Tss64};

// VM creation magic numbers
const KVM_CREATE_VM: u64 = 0xae01;
const KVM_SET_USER_MEMORY_REGION: u64 = 0x4020ae46;
const KVM_CREATE_VCPU: u64 = 0xae41;
const KVM_GET_VCPU_MMAP_SIZE: u64 = 0xae04;
const KVM_GET_SUPPORTED_CPUID: u64 = 0xc008ae05;
const KVM_SET_CPUID2: u64 = 0x4008ae90;

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

#[allow(unused)]
pub struct KvmVm {
    pub kvm_handle: File,
    pub vm_handle: File,
    pub vcpu_handle: File,
    pub guest_mem: *mut c_void,
    pub guest_mem_size: usize,
    pub run_info: *mut KvmRun,
    pub run_size: usize,
    pub gdt_table: Option<GdtPointer>,
    pub page_table: Option<u64>,
    pub tss_structure: Option<u64>,
    pub stop_flag: Arc<AtomicBool>,
    pub early_end_flag: Arc<AtomicBool>
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
    pub request_interrupt_window: u8,
    pub immediate_exit: u8,
    pub padding1: [u8; 6],
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
    pub gdt: KvmDtable,
    pub idt: KvmDtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4]
}

#[repr(C)]
pub struct KvmCpuid2 {
    pub nent: u32,
    pub padding: u32,
    pub entries: [KvmCpuidEntry2; 256]
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct KvmCpuidEntry2 {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub padding: [u32; 3]
}

impl Drop for KvmVm {
    fn drop(&mut self) {
        unsafe {
            munmap(self.run_info as *mut c_void, self.run_size);
            munmap(self.guest_mem, self.guest_mem_size);
        }
    }
}

unsafe impl Send for KvmVm {}

impl Hypervisor for KvmVm {
    fn create_vm(memory_mb: usize) -> io::Result<Self> where Self: Sized {
        // Open KVM file (which tells the kernel that we want to use KVM)
        let kvm = File::open("/dev/kvm")?;
        let kvm_fd = kvm.as_raw_fd();
        
        // Use ioctl and the create VM magic number to tell KVM to create a VM
        let vm_fd = unsafe {
            ioctl(kvm_fd, KVM_CREATE_VM, 0)
        };
        if vm_fd == -1 {
            panic!("vm ioctl failed");
        }
        let vm = unsafe { File::from_raw_fd(vm_fd) };
        
        // Convert the MBs into bytes and mmap the host memory by giving read/write perms and not associating it with a specific file
        let mem_size = match memory_mb.checked_mul(1024 * 1024) {
            Some(val) => val,
            None => return Err(Error::new(io::ErrorKind::Other, "Memory allocated too large for architecture"))
        };
        let mem = unsafe {
            mmap(null_mut(), mem_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
        };
        if mem == MAP_FAILED {
            let err = Error::last_os_error();
            panic!("mem mmap failed: {}", err);
        }
        
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
        };
        
        // Use ioctl and the create vCPU magic number to tell KVM to add a single vCPU to the VM
        let vcpu_fd = unsafe {
            ioctl(vm.as_raw_fd(), KVM_CREATE_VCPU, 0)
        };
        if vcpu_fd == -1 {
            panic!("create vcpu failed");
        }
        let vcpu = unsafe { File::from_raw_fd(vcpu_fd) };
        
        let mut cpuid_supported = KvmCpuid2 {
            nent: 256,
            padding: 0,
            entries: [KvmCpuidEntry2::default(); 256]
        };
        
        let sup = unsafe { ioctl(kvm_fd, KVM_GET_SUPPORTED_CPUID, &mut cpuid_supported) };
        if sup == -1 {
            println!("GET_SUPPORTED_CPUID failed: {}", std::io::Error::last_os_error());
        }
        let set = unsafe { ioctl(vcpu_fd, KVM_SET_CPUID2, &mut cpuid_supported) };
        if set == -1 {
            println!("GET_SET_CPUID2 failed: {}", std::io::Error::last_os_error());
        }
        
        // Use ioctl and tell KVM how large the run data will be
        let run_size = unsafe {
            ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0)
        };
        if run_size == -1 {
            panic!("run_size ioctl failed");
        }
        // Actually mmap the run data
        let run = unsafe {
            mmap(null_mut(), run_size as usize, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu.as_raw_fd(), 0)
        };
        
        if run == MAP_FAILED {
            let err = Error::last_os_error();
            panic!("run mmap failed: {}", err);
        }
        
        let kvm_run = run as *mut KvmRun;
        
        Ok(KvmVm {
            kvm_handle: kvm,
            vm_handle: vm,
            vcpu_handle: vcpu,
            guest_mem: mem,
            guest_mem_size: mem_size,
            run_info: kvm_run,
            run_size: run_size as usize,
            gdt_table: None,
            page_table: None,
            tss_structure: None,
            stop_flag: Arc::new(AtomicBool::new(false)),
            early_end_flag: Arc::new(AtomicBool::new(false))
        })
    }
    
    fn load_binary(&mut self, data: &[u8], guest_addr: u64) -> io::Result<()> {
        let end_addr = guest_addr.checked_add(data.len() as u64).ok_or(Error::new(io::ErrorKind::Other, "Address overflow"))?;
        if self.guest_mem_size <  end_addr as usize {
            return Err(Error::new(io::ErrorKind::Other, "Guest memory underallocated"));
        }
        
        // This does not check for canonicality currently, have to fix later
        let start = self.guest_mem as u64 + guest_addr;
        
        unsafe { copy_nonoverlapping(data.as_ptr(), start as *mut u8, data.len()) };
        
        Ok(())
    }
    
    fn setup_gdt(&mut self, guest_gdt_addr: u64, cpu_mode: CpuMode) {
        if cpu_mode == CpuMode::Protected {
            let gdt_table: [GdtEntry; 4] = [
                GdtEntry::new(0, 0, 0, 0),
                GdtEntry::new(0, 0xFFFFF, 0x9A, 0xC),
                GdtEntry::new(0, 0xFFFFF, 0x92, 0xC),
                GdtEntry::new(self.tss_structure.unwrap(), 0x67, 0x89, 0x0)
            ];

            let gdt_size = size_of_val(&gdt_table);

            let bytes = unsafe { from_raw_parts(gdt_table.as_ptr() as *const u8, gdt_size) };
            let start = self.guest_mem as u64 + guest_gdt_addr;
            unsafe { copy_nonoverlapping(bytes.as_ptr(), start as *mut u8, bytes.len()); }

            self.gdt_table = Some(GdtPointer {
                limit: (gdt_size - 1) as u16,
                base: guest_gdt_addr,
            });
        }
        else if cpu_mode == CpuMode::Long {
            let gdt_table: [GdtEntry; 4] = [
                GdtEntry::new(0, 0, 0, 0),
                GdtEntry::new(0, 0xFFFFF, 0x9A, 0xA),
                GdtEntry::new(0, 0xFFFFF, 0x92, 0xC),
                GdtEntry::new(self.tss_structure.unwrap(), 0x67, 0x89, 0x0),
            ];
            
            let tss_upper = (self.tss_structure.unwrap() >> 32).to_le_bytes();
            let gdt_size = size_of_val(&gdt_table);

            let bytes = unsafe { from_raw_parts(gdt_table.as_ptr() as *const u8, gdt_size) };
            let start = self.guest_mem as u64 + guest_gdt_addr;
            unsafe { copy_nonoverlapping(bytes.as_ptr(), start as *mut u8, bytes.len()); }
            let end_gdt = start + bytes.len() as u64;
            unsafe { copy_nonoverlapping(tss_upper.as_ptr(), end_gdt as *mut u8, 8); }
            
            let final_gdt_size = gdt_size + size_of::<u64>();

            self.gdt_table = Some(GdtPointer {
                limit: (final_gdt_size - 1) as u16,
                base: guest_gdt_addr,
            });
        }
    }
    
    fn setup_pts(&mut self, memory_mb: usize, cpu_mode: CpuMode) {
        if cpu_mode == CpuMode::Long {
            let num_entries = memory_mb * 1024 * 1024 / 4096;
            let num_pts = num_entries.div_ceil(512);
            let num_pds = num_pts.div_ceil(512);
            let num_pdpts = num_pds.div_ceil(512);
            let num_pml4s = num_pdpts.div_ceil(512);
            
            let size_bytes = (num_pts + num_pds + num_pdpts + num_pml4s) * 4096;
            let start_guest_addr = self.guest_mem_size - size_bytes;
            let start_host_addr = self.guest_mem as usize + start_guest_addr;
            
            let pml4s_base_guest = start_guest_addr;
            let pdpt_base_guest = start_guest_addr + (0x1000 * num_pml4s);
            let pd_base_guest = pdpt_base_guest + (0x1000 * num_pdpts);
            let pt_base_guest = pd_base_guest + (0x1000 * num_pds);
            
            let pml4s_base_host = start_host_addr;
            let pdpt_base_host = start_host_addr + (0x1000 * num_pml4s);
            let pd_base_host = pdpt_base_host + (0x1000 * num_pdpts);
            let pt_base_host = pd_base_host + (0x1000 * num_pds);
            
            for i in 0..num_entries {
                let entry_location = pt_base_host + (i * 8);
                let entry = (i * 0x1000) | 0x03;
                unsafe { *(entry_location as *mut u64) = entry as u64; }
            }
            for i in 0..num_pts {
                let entry_location = pd_base_host + (i * 8);
                let entry = pt_base_guest + (i * 0x1000) | 0x03;
                unsafe { *(entry_location as *mut u64) = entry as u64; }
            }
            for i in 0..num_pds {
                let entry_location = pdpt_base_host + (i * 8);
                let entry = pd_base_guest + (i * 0x1000) | 0x03;
                unsafe { *(entry_location as *mut u64) = entry as u64; }
            }
            for i in 0..num_pdpts {
                let entry_location = pml4s_base_host + (i * 8);
                let entry = pdpt_base_guest + (i * 0x1000) | 0x03;
                unsafe { *(entry_location as *mut u64) = entry as u64; }
            }
            
            self.page_table = Some(pml4s_base_guest as u64)
        }
    }
    
    fn setup_tss(&mut self, cpu_mode: CpuMode) -> io::Result<()> {
        if cpu_mode == CpuMode::Protected {
            let mut tss = Tss32::default();
            let tss_size = size_of_val(&tss);
            let stack_addr = self.guest_mem_size - tss_size; // Handle conversion into u32 with try_into later
            tss.esp0 = stack_addr as u32;
            tss.ss0 = 0x10;
            
            let bytes = unsafe { from_raw_parts(&tss as *const Tss32 as *const u8, tss_size) };
            let start = self.guest_mem as usize + stack_addr;
            unsafe { copy_nonoverlapping(bytes.as_ptr(), start as *mut u8, bytes.len()) };
            self.tss_structure = Some(stack_addr as u64);
        }
        else if cpu_mode == CpuMode::Long {
            let mut tss = Tss64::default();
            let tss_size = size_of_val(&tss);
            let stack_addr = self.page_table.unwrap() - tss_size as u64; // Also doubles as the tss_addr
            tss.rsp0 = stack_addr;
            
            let tss_size = size_of_val(&tss);
            let bytes = unsafe { from_raw_parts(&tss as *const Tss64 as *const u8, tss_size) };
            let start = self.guest_mem as u64 + stack_addr;
            unsafe { copy_nonoverlapping(bytes.as_ptr(), start as *mut u8, bytes.len()) };
            self.tss_structure = Some(stack_addr);
        };
        
        Ok(())
    }
    
    fn set_entry_point(&mut self, addr: u64, cpu_mode: CpuMode) -> io::Result<()> {
        let mut regs = KvmRegs::default();
        let mut sregs = KvmSregs::default();
        
        let get_regs = unsafe { ioctl(self.vcpu_handle.as_raw_fd(), KVM_GET_REGS, &mut regs) };
        if get_regs == -1 {
            return Err(Error::last_os_error());
        }
        
        let get_sregs = unsafe { ioctl(self.vcpu_handle.as_raw_fd(), KVM_GET_SREGS, &mut sregs) };
        if get_sregs == -1 {
            return Err(Error::last_os_error());
        }
        
        regs.rip = addr;
        regs.rflags = 0x2;
        match cpu_mode {
            CpuMode::Real => {
                sregs.cs.base = 0;
                sregs.cs.selector = 0;
                sregs.cs.limit = 0xFFFF;
            }
            CpuMode::Protected => {
                sregs.cs.base = 0;
                sregs.cs.selector = 0x08;
                sregs.cs.limit = 0xFFFFFFFF;
                sregs.cs.type_ = 0xB;
                sregs.cs.s = 1;
                sregs.cs.dpl = 0;
                sregs.cs.present = 1;
                sregs.cs.avl = 0;
                sregs.cs.l = 0;
                sregs.cs.db = 1;
                sregs.cs.g = 1;
                
                sregs.ds.base = 0;
                sregs.ds.selector = 0x10;
                sregs.ds.limit = 0xFFFFFFFF;
                sregs.ds.type_ = 0x03;
                sregs.ds.s = 1;
                sregs.ds.dpl = 0;
                sregs.ds.present = 1;
                sregs.ds.avl = 0;
                sregs.ds.l = 0;
                sregs.ds.db = 1;
                sregs.ds.g = 1;
                
                sregs.ss.base = 0;
                sregs.ss.selector = 0x10;
                sregs.ss.limit = 0xFFFFFFFF;
                sregs.ss.type_ = 0x03;
                sregs.ss.s = 1;
                sregs.ss.dpl = 0;
                sregs.ss.present = 1;
                sregs.ss.avl = 0;
                sregs.ss.l = 0;
                sregs.ss.db = 1;
                sregs.ss.g = 1;
                
                sregs.cr0 = 0x11;
                
                sregs.tr.base = self.tss_structure.ok_or_else(|| Error::new(ErrorKind::Other, "TSS not set up correctly"))?;
                sregs.tr.selector = 0x18;
                sregs.tr.limit = 0x67;
                sregs.tr.type_ = 0xB;
                sregs.tr.s = 0;
                sregs.tr.dpl = 0;
                sregs.tr.present = 1;
                sregs.tr.avl = 0;
                sregs.tr.l = 0;
                sregs.tr.db = 0;
                sregs.tr.g = 0;
                
                sregs.gdt.base = (self.gdt_table.as_ref().ok_or_else(|| {
                    Error::new(
                        io::ErrorKind::Other,
                        "Base field in GDT table not set up correctly",
                    )
                })?)
                .base;
                sregs.gdt.limit = (self.gdt_table.as_ref().ok_or_else(|| {
                    Error::new(
                        io::ErrorKind::Other,
                        "Limit field in GDT table not set up correctly",
                    )
                })?)
                .limit;
            }
            CpuMode::Long => {
                sregs.cs.base = 0;
                sregs.cs.selector = 0x08;
                sregs.cs.limit = 0xFFFF;
                sregs.cs.type_ = 0xB;
                sregs.cs.s = 1;
                sregs.cs.dpl = 0;
                sregs.cs.present = 1;
                sregs.cs.avl = 0;
                sregs.cs.l = 1;
                sregs.cs.db = 0;
                sregs.cs.g = 1;
                
                sregs.ds.base = 0;
                sregs.ds.selector = 0x10;
                sregs.ds.limit = 0xFFFFFFFF;
                sregs.ds.type_ = 0x03;
                sregs.ds.s = 1;
                sregs.ds.dpl = 0;
                sregs.ds.present = 1;
                sregs.ds.avl = 0;
                sregs.ds.l = 0;
                sregs.ds.db = 1;
                sregs.ds.g = 1;
                
                sregs.ss.base = 0;
                sregs.ss.selector = 0x10;
                sregs.ss.limit = 0xFFFFFFFF;
                sregs.ss.type_ = 0x03;
                sregs.ss.s = 1;
                sregs.ss.dpl = 0;
                sregs.ss.present = 1;
                sregs.ss.avl = 0;
                sregs.ss.l = 0;
                sregs.ss.db = 1;
                sregs.ss.g = 1;
                
                sregs.tr.base = self.tss_structure.ok_or_else(|| Error::new(ErrorKind::Other, "TSS not set up correctly"))?;
                sregs.tr.selector = 0x18;
                sregs.tr.limit = 0x67;
                sregs.tr.type_ = 0xB;
                sregs.tr.s = 0;
                sregs.tr.dpl = 0;
                sregs.tr.present = 1;
                sregs.tr.avl = 0;
                sregs.tr.l = 0;
                sregs.tr.db = 0;
                sregs.tr.g = 0;
                
                sregs.cr3 = (self.page_table).ok_or_else(|| {
                    Error::new(ErrorKind::Other, "Page tables not set up correctly")
                })?;
                sregs.cr4 = 0x20;
                sregs.efer = 0x500;
                sregs.cr0 = 0x80000001;
                sregs.gdt.base = (self.gdt_table.as_ref().ok_or_else(|| {
                    Error::new(
                        io::ErrorKind::Other,
                        "Base field in GDT table not set up correctly",
                    )
                })?)
                .base;
                sregs.gdt.limit = (self.gdt_table.as_ref().ok_or_else(|| {
                    Error::new(
                        io::ErrorKind::Other,
                        "Limit field in GDT table not set up correctly",
                    )
                })?)
                .limit;
            }
        }
        
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
    
    fn run(&mut self, tx: &Sender<CancelToken>) -> ExitReason {
        let thread_id = unsafe { libc::pthread_self() };
        let _ = tx.send(thread_id);
        // This is here for weird sync issue, it fixed the register pointer issue
        let mut regs = KvmRegs::default();
        unsafe { ioctl(self.vcpu_handle.as_raw_fd(), KVM_GET_REGS, &mut regs) };
        
        loop {
            let ret = unsafe { ioctl(self.vcpu_handle.as_raw_fd(), KVM_RUN) };
            if ret == 0 {
                break;
            }
            
            let err = errno::errno().0;
            if err == EINTR {
                if self.stop_flag.load(Ordering::Relaxed) == true {
                    return ExitReason::Shutdown;
                }
                continue;
            }
            
            self.early_end_flag.store(true, Ordering::Relaxed);
            return ExitReason::Error(format!("KVM_RUN failed: errno = {}", err));
        }
        
        self.early_end_flag.store(true, Ordering::Relaxed);
        
        unsafe  {
            match (*self.run_info).exit_reason as u64 {
                KVM_EXIT_IO => {
                    let io = &(*self.run_info).union.io;
                    match io.direction {
                        0 => {
                            if io.port == 0x3FD {
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
                                
                                let data_ptr = (self.run_info as *mut u8).add(io.data_offset as usize);
                                *data_ptr = 0x20;
                            }
                            
                            ExitReason::IoIn { port: io.port, size: io.size as usize }
                        },
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