mod hypervisor;
mod vm;
mod loader;

use anyhow::Result;
#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::WHvCancelRunVirtualProcessor;
#[cfg(target_os = "linux")]
use libc::pthread_kill;

use clap::{Parser, Subcommand};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use dunce::canonicalize;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{RecvTimeoutError, Sender, channel};
use std::{fs, thread};
use std::time::Duration;
use notify::RecursiveMode;
use notify_debouncer_mini::new_debouncer;
use ctrlc;

use crate::hypervisor::{CancelToken, GuestInfo, Register};
use crate::vm::{AnvilVm, VmExitReason};
use crate::loader::{LoadedKernel, parse_kernel};

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
    // Add multiple load args later
    Run {
        kernel_file: String,
        
        #[arg(short, long, default_value = "16")]
        memory: usize,
        
        #[arg(long, default_value = "rsi")]
        mem_reg: Register,
        
        #[arg(short, long)]
        load: Option<String>,
        
        #[arg(long, value_enum, default_value = "rdi", requires = "load")]
        load_reg: Option<Register>
    },
    Watch {
        kernel_file: String,
        
        #[arg(short, long, default_value = "16")]
        memory: usize,
        
        #[arg(short, long, default_value = "rsi")]
        mem_reg: Register,
        
        #[arg(short, long)]
        load: Option<String>,
        
        #[arg(long, value_enum, default_value = "rdi", requires = "load")]
        load_reg: Option<Register>
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Run { kernel_file, memory, mem_reg, load, load_reg } => {
            let (tx, ..) = channel::<CancelToken>();
            match load {
                Some (ref path) => {
                    let guest_kernel = parse_kernel(path)?;
                    let guest_info = GuestInfo { guest_addr: guest_kernel.entry_point, load_reg: load_reg.unwrap() };
                    run_vm(&kernel_file, memory, mem_reg, Some(path), Some(guest_kernel), Some(guest_info), &tx)?;
                }
                None => {
                    run_vm(&kernel_file, memory, mem_reg, None, None, None, &tx)?;
                }
            }
        },
        Commands::Watch { kernel_file, memory, mem_reg, load, load_reg } => {
            #[cfg(target_os = "linux")]
            {
                extern "C" fn interrupt_handler(_: libc::c_int) {}
                unsafe { libc::signal(libc::SIGUSR1, interrupt_handler as *const() as libc::sighandler_t) };
            }
            
            let ctrl_c = Arc::new(AtomicBool::new(false));
            let ctrl_c_clone = ctrl_c.clone();
            
            let watch_handle = thread::spawn(move || -> Result<()> {
                let (tx_watcher, rx_watcher) = channel();
                
                let mut debouncer = new_debouncer(Duration::from_millis(500), tx_watcher).expect("Failed to create debouncer");
                let path = Path::new(&kernel_file);
                let parent = path.parent().unwrap_or(Path::new("."));
                debouncer.watcher().watch(parent, RecursiveMode::NonRecursive).expect("Failed to watch parent directory");
                
                'outer: loop {
                    let kernel = parse_kernel(&kernel_file)?;
                    
                    println!("[Anvil] Loading kernel: {} ({} bytes)", &kernel_file, kernel.segments.iter().map(|segment| segment.data.len()).sum::<usize>());
                    
                    let (mut vm, stop_flag, early_end_flag) = AnvilVm::create_vm(memory)?;
                    vm.setup_reqs(memory, 0x0000, kernel.cpu_mode)?;
                    for bin in kernel.segments.iter() {
                        vm.load_binary(&bin.data, bin.guest_addr)?;
                    }
                    match load {
                        Some(ref path) => {
                            let guest = parse_kernel(path)?;
                            for bin in guest.segments.iter() {
                                vm.load_binary(&bin.data, bin.guest_addr)?;
                            }
                            vm.set_entry_point(
                                mem_reg,
                                kernel.entry_point,
                                Some(GuestInfo { guest_addr: guest.entry_point, load_reg: load_reg.unwrap() }),
                                kernel.cpu_mode
                            )?;
                            println!("[Anvil] Loading guest: {} ({} bytes) -> {:#?}", path, guest.segments.iter().map(|segment| segment.data.len()).sum::<usize>(), load_reg.unwrap());
                        }
                        None => {
                            vm.set_entry_point(mem_reg, kernel.entry_point, None, kernel.cpu_mode)?;
                        }
                    }
                    println!("[Anvil] Memory allocated: {} MB -> {:#?}", memory, mem_reg);
                    
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
                    
                    let contents_init = fs::read(&kernel_file)?;
                    let current_init = simple_hash(&contents_init);
                    let mut last_hash = current_init;
                    
                    loop {
                        match rx_watcher.recv_timeout(Duration::from_millis(100)) {
                            Ok(Ok(events)) => {
                                let mut file_found = false;
                                for event in events.iter() {
                                    if event.path == canonicalize(path)? {
                                        let contents = fs::read(&kernel_file)?;
                                        let current_hash = simple_hash(&contents);
                                                                                
                                        if last_hash == current_hash {
                                            continue;
                                        }
                                        else {
                                            last_hash = current_hash;
                                            file_found = true;
                                            break;
                                        }
                                    }
                                }
                                if !file_found {
                                    continue;
                                }
                                println!("\nFile changed, triggering refresh...\n");
                                if !early_end_flag.load(Ordering::Relaxed) {
                                    stop_flag.store(true, Ordering::Relaxed);
                                    cancel(cancel_token)?;
                                    stop_flag.store(false, Ordering::Relaxed);
                                    early_end_flag.store(false, Ordering::Relaxed);
                                }
                                vm_handle.join().unwrap();
                                break;
                            }
                            Ok(Err(e)) => {
                                eprintln!("Watch error: {:?}", e);
                            }
                            Err(RecvTimeoutError::Timeout) => {
                                if ctrl_c_clone.load(Ordering::Relaxed) {
                                    break 'outer;
                                }
                            }
                            Err(_) => break 'outer
                        }
                    }
                }
                
                Ok(())
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

fn run_vm(kernel_file: &String, memory: usize, mem_reg: Register, guest_file: Option<&String>, guest_kernel: Option<LoadedKernel>, guest_info: Option<GuestInfo>, tx: &Sender<CancelToken>) -> Result<()> {
    let kernel = parse_kernel(&kernel_file)?;
    
    println!("[Anvil] Loading kernel: {} ({} bytes)", &kernel_file, kernel.segments.iter().map(|segment| segment.data.len()).sum::<usize>());
    
    let mut vm = AnvilVm::create_vm(memory)?;
    vm.0.setup_reqs(memory, 0x0000, kernel.cpu_mode)?;
    for bin in kernel.segments.iter() {
        vm.0.load_binary(&bin.data, bin.guest_addr)?;
    }
    match guest_kernel {
        Some(kernel) => {
            println!("[Anvil] Loading guest: {} ({} bytes) -> {:#?}", guest_file.unwrap(), kernel.segments.iter().map(|segment| segment.data.len()).sum::<usize>(), guest_info.as_ref().unwrap().load_reg);
            for bin in kernel.segments.iter() {
                vm.0.load_binary(&bin.data, bin.guest_addr)?;
            }
        }
        None => ()
    }
    
    println!("[Anvil] Memory allocated: {} MB -> {:#?}", memory, mem_reg);
    
    vm.0.set_entry_point(mem_reg, kernel.entry_point, guest_info, kernel.cpu_mode)?;
    let exit_reason = vm.0.run(&tx);
    match exit_reason {
        VmExitReason::Halt => println!("[Anvil] VM exited successfully (Halt)"),
        VmExitReason::Shutdown => println!("[Anvil] VM exited successfully (Shutdown)"),
        VmExitReason::FailEntry(string) => println!("[Anvil] VM exited with a failure (Fail Entry): {}", string),
        VmExitReason::InternalError(string) => println!("[Anvil] VM exited with a failure (Internal Error): {}", string),
        VmExitReason::Error(string) => println!("[Anvil] VM exited with a failure (Unknown): {}", string)
    };
    
    Ok(())
}

fn simple_hash(data: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish()
}

fn cancel(cancel_token: CancelToken) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        if cancel_token.0 != 0 && cancel_token.0 != -1 {
            unsafe { WHvCancelRunVirtualProcessor(cancel_token, 0, 0) }?;
        }
    }
    #[cfg(target_os = "linux")]
    {
        unsafe { pthread_kill(cancel_token, libc::SIGUSR1) };
    }
    
    Ok(())
}