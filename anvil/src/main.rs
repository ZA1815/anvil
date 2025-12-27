mod hypervisor;
mod vm;
mod loader;

use anyhow::Result;
use clap::{Parser, Subcommand};
#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::WHvCancelRunVirtualProcessor;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{RecvTimeoutError, Sender, channel};
use std::thread;
use std::time::Duration;
use notify::{RecommendedWatcher, RecursiveMode, Watcher, Config};
use notify_debouncer_mini::{new_debouncer, DebouncedEventKind};
use ctrlc;

use crate::hypervisor::CancelToken;
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Run { kernel_file, memory } => {
            let (tx, ..) = channel::<CancelToken>();
            run_vm(&kernel_file, memory, &tx)?;
        },
        Commands::Watch { kernel_file, memory } => {
            let ctrl_c = Arc::new(AtomicBool::new(false));
            let ctrl_c_clone = ctrl_c.clone();
            
            let watch_handle = thread::spawn(move || -> Result<()> {
                let (tx_watcher, rx_watcher) = channel();
                
                let mut debouncer = new_debouncer(Duration::from_millis(500), tx_watcher).expect("Failed to create debouncer");
                let path = Path::new(&kernel_file);
                let parent = path.parent().unwrap_or(Path::new("."));
                debouncer.watcher().watch(parent, RecursiveMode::NonRecursive).expect("Failed to watch parent directory");
                
                loop {
                    let kernel = parse_kernel(&kernel_file)?;
                    
                    println!("[Anvil] Loading kernel: {} ({} bytes)", &kernel_file, kernel.segments.iter().map(|segment| segment.data.len()).sum::<usize>());
                    println!("[Anvil] Memory allocated: {} MB", memory);
                    
                    let (mut vm, stop_flag) = AnvilVm::create_vm(memory)?;
                    vm.setup_gdt(0x0000, kernel.cpu_mode);
                    vm.setup_pts(memory, kernel.cpu_mode);
                    for bin in kernel.segments.iter() {
                        vm.load_binary(&bin.data, bin.guest_addr)?;
                    }
                    vm.set_entry_point(kernel.entry_point, kernel.cpu_mode)?;
                    
                    let (tx_token, rx_token) = channel::<CancelToken>();
                    
                    let vm_handle = thread::spawn(move || {
                        let exit_reason = vm.run(&tx_token);
                        match exit_reason {
                            VmExitReason::Halt => println!("[Anvil] VM exited successfully (Halt)"),
                            VmExitReason::Shutdown => println!("[Anvil] VM exited successfully (Shutdown)"),
                            VmExitReason::FailEntry(string) => println!("[Anvil] VM exited with a failure (Fail Entry): {}", string),
                            VmExitReason::InternalError(string) => println!("[Anvil] VM exited with a failure (Internal Error): {}", string),
                            VmExitReason::Error(string) => println!("[Anvil] VM exited with a failure (Unknown): {}", string)
                        };
                    });
                    
                    let cancel_token = rx_token.recv().expect("VM thread died before sending cancel token");
                    
                    loop {
                        match rx_watcher.recv_timeout(Duration::from_millis(100)) {
                            Ok(Ok(_)) => {
                                println!("File changed, triggering refresh...");
                                stop_flag.store(true, Ordering::Relaxed);
                                #[cfg(target_os = "windows")]
                                unsafe { WHvCancelRunVirtualProcessor(cancel_token, 0, 0) }?;
                                vm_handle.join().unwrap();
                                stop_flag.store(false, Ordering::Relaxed);
                                break;
                            }
                            Ok(Err(e)) => {
                                eprintln!("Watch error: {:?}", e);
                            }
                            Err(RecvTimeoutError::Timeout) => {
                                if ctrl_c_clone.load(Ordering::Relaxed) {
                                    return Ok(());
                                }
                            }
                            Err(_) => return Ok(())
                        }
                    }
                }
            });
            
            ctrlc::set_handler(move || {
                println!("[Anvil] Shutting down...");
                ctrl_c.store(true, Ordering::Relaxed);
            }).expect("Error setting Ctrl+C handler");
            
            watch_handle.join().unwrap()?;
        }
    }
    
    Ok(())
}

fn run_vm(kernel_file: &String, memory: usize, tx: &Sender<CancelToken>) -> Result<Arc<AtomicBool>> {
    let kernel = parse_kernel(&kernel_file)?;
    
    println!("[Anvil] Loading kernel: {} ({} bytes)", &kernel_file, kernel.segments.iter().map(|segment| segment.data.len()).sum::<usize>());
    println!("[Anvil] Memory allocated: {} MB", memory);
    
    let mut vm = AnvilVm::create_vm(memory)?;
    vm.0.setup_gdt(0x0000, kernel.cpu_mode);
    vm.0.setup_pts(memory, kernel.cpu_mode);
    for bin in kernel.segments.iter() {
        vm.0.load_binary(&bin.data, bin.guest_addr)?;
    }
    vm.0.set_entry_point(kernel.entry_point, kernel.cpu_mode)?;
    let exit_reason = vm.0.run(&tx);
    match exit_reason {
        VmExitReason::Halt => println!("[Anvil] VM exited successfully (Halt)"),
        VmExitReason::Shutdown => println!("[Anvil] VM exited successfully (Shutdown)"),
        VmExitReason::FailEntry(string) => println!("[Anvil] VM exited with a failure (Fail Entry): {}", string),
        VmExitReason::InternalError(string) => println!("[Anvil] VM exited with a failure (Internal Error): {}", string),
        VmExitReason::Error(string) => println!("[Anvil] VM exited with a failure (Unknown): {}", string)
    };
    
    Ok(vm.1)
}