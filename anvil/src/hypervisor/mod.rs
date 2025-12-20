use std::io::Result;
#[cfg(unix)]
mod kvm;

trait Hypervisor {
    fn create_vm(memory_mb: usize) -> Result<Self> where Self: Sized;
    fn load_binary(&mut self, data: &[u8], guest_addr: u64) -> Result<()>;
    fn run(&mut self) -> Result<ExitReason>;
}

pub enum ExitReason {
    Halt,
    IoOut { port: u16, data: Vec<u8> },
    IoIn { port: u16, size: usize },
    Shutdown,
    Error(String),
    DebugPoint
}