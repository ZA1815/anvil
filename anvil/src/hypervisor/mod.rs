use std::io::Result;

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

pub trait Hypervisor {
    fn create_vm(memory_mb: usize) -> Result<Self> where Self: Sized;
    fn load_binary(&mut self, data: &[u8], guest_addr: u64) -> Result<()>;
    fn setup_gdt(&mut self, guest_gdt_addr: u64, cpu_mode: CpuMode);
    fn setup_pts(&mut self, memory_mb: usize, cpu_mode: CpuMode);
    // Before releasing, make sure that GDT is loaded after binaries/elf
    fn set_entry_point(&mut self, addr: u64, cpu_mode: CpuMode) -> Result<()>;
    fn run(&mut self) -> ExitReason;
}

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
    pub const fn new(base: u32, limit: u32, access: u8, flags: u8) -> Self {
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