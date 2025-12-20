use std::io::Result;

trait Hypervisor {
    fn create_vm(memory_mb: usize) -> Result<Self> where Self: Sized;
    fn load_binary(&mut self, binary: &[u8], entry: u64) -> Result<()>;
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

pub struct MockVm;

impl Hypervisor for MockVm {
    fn create_vm(memory_mb: usize) -> Result<Self> {
        Ok(Self)
    }
    
    fn load_binary(&mut self, binary: &[u8], entry: u64) -> Result<()> {
        Ok(())
    }
    
    fn run(&mut self) -> Result<ExitReason> {
        Ok(ExitReason::Halt)
    }
}