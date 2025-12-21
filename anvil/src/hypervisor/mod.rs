use std::io::Result;

#[cfg(target_os = "linux")]
mod kvm;
#[cfg(target_os = "windows")]
mod hyperv;

trait Hypervisor {
    fn create_vm(memory_mb: usize) -> Result<Self> where Self: Sized;
    fn load_binary(&mut self, data: &[u8], guest_addr: u64) -> Result<()>;
    fn set_entry_point(&mut self, addr: u64) -> Result<()>;
    fn run(&mut self) -> ExitReason;
}

pub enum ExitReason {
    Halt,
    IoOut { port: u16, data: Vec<u8> },
    IoIn { port: u16, size: usize },
    Shutdown,
    FailEntry,
    InternalError,
    Error(String),
    DebugPoint
}