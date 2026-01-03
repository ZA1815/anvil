use std::{io::Result, sync::mpsc::Sender};
use clap::ValueEnum;

#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE;

#[cfg(target_os = "linux")]
mod kvm;
#[cfg(target_os = "windows")]
mod hyperv;
#[cfg(target_os = "macos")]
mod hvF;

#[cfg(target_os = "linux")]
pub type PlatformHypervisor = kvm::KvmVm;
#[cfg(target_os = "windows")]
pub type PlatformHypervisor = hyperv::HyperVVm;
#[cfg(target_os = "macos")]
pub type PlatformHypervisor = hvF::HvFVm;

#[cfg(target_os = "linux")]
pub type CancelToken = libc::pthread_t;
#[cfg(target_os = "windows")]
pub type CancelToken = WHV_PARTITION_HANDLE;
// Add for macOS later

pub trait Hypervisor {
    fn create_vm(memory_mb: usize) -> Result<Self> where Self: Sized;
    fn load_binary(&mut self, data: &[u8], guest_addr: u64) -> Result<()>;
    fn setup_gdt(&mut self, guest_gdt_addr: u64, cpu_mode: CpuMode);
    fn setup_pts(&mut self, memory_mb: usize, cpu_mode: CpuMode);
    fn setup_tss(&mut self, cpu_mode: CpuMode) -> Result<()>;
    // Before releasing, make sure that GDT is loaded after binaries/elf
    fn set_entry_point(&mut self, mem_reg: Register, exec_addr: u64, guest_info: Option<GuestInfo>, cpu_mode: CpuMode) -> Result<()>;
    fn run(&mut self, tx: &Sender<CancelToken>) -> ExitReason;
}

#[allow(unused)]
pub enum ExitReason {
    Halt,
    IoOut { port: u16, data: Vec<u8> },
    IoIn { port: u16, size: usize },
    Shutdown,
    FailEntry { hardware_reason: u64, cpu: u32 },
    InternalError { suberror: u32, data: Vec<u64> },
    Error(String),
    DebugPoint
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum CpuMode {
    Real,
    Protected,
    Long
}

#[derive(ValueEnum, Copy, Clone, Debug)]
pub enum Register {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15
}

pub struct GuestInfo {
    pub guest_addr: u64,
    pub load_reg: Register
}

// GDT logic to enter 32-bit protected mode
#[repr(C, packed)]
pub struct GdtPointer {
    pub limit: u16,
    pub base: u64
}

#[repr(C, packed)]
pub struct GdtEntry {
    pub limit_low: u16,
    pub base_low: u16,
    pub base_mid: u8,
    pub access: u8,
    pub granularity: u8,
    pub base_high: u8
}

impl GdtEntry {
    pub const fn new(base: u64, limit: u32, access: u8, flags: u8) -> Self {
        Self {
            limit_low: (limit & 0xFFFF) as u16,
            base_low: (base & 0xFFFF) as u16,
            base_mid: ((base >> 16) & 0xFF) as u8,
            access,
            granularity: (((limit >> 16) & 0x0F) as u8) | ((flags & 0x0F) << 4),
            base_high: ((base >> 24) & 0xFF) as u8
        }
    }
}

// TSS structs
#[repr(C, packed)]
#[derive(Default)]
pub struct Tss32 {
    pub prev_task_link: u16,
    pub reserved0: u16,
    pub esp0: u32,
    pub ss0: u16,
    pub reserved1: u16,
    pub esp1: u32,
    pub ss1: u16,
    pub reserved2: u16,
    pub esp2: u32,
    pub ss2: u16,
    pub reserved3: u16,
    pub cr3: u32,
    pub eip: u32,
    pub eflags: u32,
    pub eax: u32,
    pub ecx: u32,
    pub edx: u32,
    pub ebx: u32,
    pub esp: u32,
    pub ebp: u32,
    pub esi: u32,
    pub edi: u32,
    pub es: u16,
    pub reserved4: u16,
    pub cs: u16,
    pub reserved5: u16,
    pub ss: u16,
    pub reserved6: u16,
    pub ds: u16,
    pub reserved7: u16,
    pub fs: u16,
    pub reserved8: u16,
    pub gs: u16,
    pub reserved9: u16,
    pub ldt_selector: u16,
    pub reserved10: u16,
    pub trap: u16,
    pub iomap_base: u16,
}

#[repr(C, packed)]
#[derive(Default)]
pub struct Tss64 {
    pub reserved0: u32,
    pub rsp0: u64,
    pub rsp1: u64,
    pub rsp2: u64,
    pub reserved1: u64,
    pub ist1: u64,
    pub ist2: u64,
    pub ist3: u64,
    pub ist4: u64,
    pub ist5: u64,
    pub ist6: u64,
    pub ist7: u64,
    pub reserved2: u64,
    pub reserved3: u16,
    pub iomap_base: u16,
}