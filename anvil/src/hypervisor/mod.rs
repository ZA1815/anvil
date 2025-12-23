use std::io::Result;

#[cfg(target_os = "linux")]
mod kvm;
#[cfg(target_os = "windows")]
mod hyperv;

#[cfg(target_os = "linux")]
pub type PlatformHypervisor = kvm::KvmVm;
#[cfg(target_os = "windows")]
pub type PlatformHypervisor = hyperv::HyperVVm;

pub trait Hypervisor {
    fn create_vm(memory_mb: usize) -> Result<Self> where Self: Sized;
    fn load_binary(&mut self, data: &[u8], guest_addr: u64) -> Result<()>;
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

#[derive(PartialEq, Debug)]
pub enum CpuMode {
    Real,
    Protected,
    Long
}