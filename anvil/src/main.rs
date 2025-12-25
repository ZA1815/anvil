mod hypervisor;
mod vm;
mod loader;

use clap::{Parser, Subcommand};

use crate::vm::{AnvilVm, VmExitReason};
use crate::loader::parse_kernel;

#[derive(Parser)]
#[command(name = "Anvil")]
#[command(about = "Disposable VM for testing bare-metal code", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands
}

#[derive(Subcommand)]
enum Commands {
    Run {
        kernel_file: String,
        
        #[arg(short, long, default_value = "16")]
        memory: usize
    },
    Watch {
        kernel_file: String,
        
        #[arg(short, long, default_value = "16")]
        memory: usize
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Run { kernel_file, memory } => {
            let kernel = parse_kernel(&kernel_file)?;
            
            println!("[Anvil] Loading kernel: {} ({} bytes)", &kernel_file, kernel.segments.iter().map(|segment| segment.data.len()).sum::<usize>());
            println!("[Anvil] Memory allocated: {} MB", memory);
            
            let mut vm = AnvilVm::create_vm(memory)?;
            vm.setup_gdt(0x0000, kernel.cpu_mode);
            vm.setup_pts(memory, kernel.cpu_mode);
            for bin in kernel.segments.iter() {
                vm.load_binary(&bin.data, bin.guest_addr)?;
            }
            vm.set_entry_point(kernel.entry_point, kernel.cpu_mode)?;
            let run = vm.run();
            match run {
                VmExitReason::Halt => println!("[Anvil] VM exited successfully (Halt)"),
                VmExitReason::Shutdown => println!("[Anvil] VM exited successfully (Shutdown)"),
                VmExitReason::FailEntry(string) => println!("[Anvil] VM exited with a failure (Fail Entry): {}", string),
                VmExitReason::InternalError(string) => println!("[Anvil] VM exited with a failure (Internal Error): {}", string),
                VmExitReason::Error(string) => println!("[Anvil] VM exited with a failure (Unknown): {}", string)
            };
        },
        Commands::Watch { kernel_file, memory } => {
            println!("Placeholder");
        }
    }
    
    Ok(())
}