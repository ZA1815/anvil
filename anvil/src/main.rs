mod hypervisor;
mod vm;

use clap::Parser;
use std::fs::read;

use crate::vm::{AnvilVm, VmExitReason};

#[derive(Parser)]
#[command(name = "Anvil")]
#[command(about = "Disposable VM for testing bare-metal code", long_about = None)]
#[command(version)]
struct Cli {
    kernel: String,
    
    #[arg(short, long, default_value = "16")]
    memory: usize
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    let binary = read(&cli.kernel)?;
    
    println!("[Anvil] Loading kernel: {} ({} bytes)", &cli.kernel, binary.len());
    println!("[Anvil] Memory allocated: {} MB", &cli.memory);
    
    let mut vm = AnvilVm::create_vm(cli.memory)?;
    vm.load_binary(&binary, 0x1000)?;
    vm.set_entry_point(0x1000)?;
    let run = vm.run();
    println!("");
    match run {
        VmExitReason::Halt => println!("[Anvil] VM exited successfully (Halt)"),
        VmExitReason::Shutdown => println!("[Anvil] VM exited successfully (Shutdown)"),
        VmExitReason::FailEntry(string) => println!("[Anvil] VM exited with a failure (Fail Entry): {}", string),
        VmExitReason::InternalError(string) => println!("[Anvil] VM exited with a failure (Internal Error): {}", string),
        VmExitReason::Error(string) => println!("[Anvil] VM exited with a failure (Unknown): {}", string)
    };
    
    Ok(())
}