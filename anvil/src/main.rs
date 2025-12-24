mod hypervisor;
mod vm;
mod loader;

use clap::Parser;

use crate::vm::{AnvilVm, VmExitReason};
use crate::loader::parse_kernel;

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
    
    let kernel = parse_kernel(&cli.kernel)?;
    
    println!("[Anvil] Loading kernel: {} ({} bytes)", &cli.kernel, kernel.segments.iter().map(|segment| segment.data.len()).sum::<usize>());
    println!("[Anvil] Memory allocated: {} MB", &cli.memory);
    
    let mut vm = AnvilVm::create_vm(cli.memory)?;
    vm.setup_gdt(0x0000, kernel.cpu_mode);
    for bin in kernel.segments.iter() {
        vm.load_binary(&bin.data, bin.guest_addr)?;
    }
    vm.set_entry_point(kernel.entry_point, kernel.cpu_mode)?;
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