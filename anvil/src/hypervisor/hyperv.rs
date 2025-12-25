use std::ffi::c_void;
use std::io::{Error, ErrorKind};
use std::mem;
use std::ptr::copy_nonoverlapping;
use std::slice::from_raw_parts;

use windows::Win32::System::Hypervisor::{
    WHV_PARTITION_HANDLE, WHV_REGISTER_NAME, WHV_REGISTER_VALUE, WHV_RUN_VP_EXIT_CONTEXT,
    WHV_X64_SEGMENT_REGISTER, WHV_X64_SEGMENT_REGISTER_0, WHV_X64_TABLE_REGISTER,
    WHvCreatePartition, WHvCreateVirtualProcessor, WHvMapGpaRange, WHvMapGpaRangeFlagExecute,
    WHvMapGpaRangeFlagRead, WHvMapGpaRangeFlagWrite, WHvPartitionPropertyCodeProcessorCount,
    WHvRunVirtualProcessor, WHvRunVpExitReasonInvalidVpRegisterValue,
    WHvRunVpExitReasonUnrecoverableException, WHvRunVpExitReasonX64Halt,
    WHvRunVpExitReasonX64IoPortAccess, WHvSetPartitionProperty, WHvSetVirtualProcessorRegisters,
    WHvSetupPartition, WHvX64RegisterCr0, WHvX64RegisterCs, WHvX64RegisterDs, WHvX64RegisterGdtr,
    WHvX64RegisterRax, WHvX64RegisterRflags, WHvX64RegisterRip, WHvX64RegisterSs
};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc};

use crate::hypervisor::{CpuMode, ExitReason, GdtEntry, GdtPointer, Hypervisor};

pub struct HyperVVm {
    pub partition: WHV_PARTITION_HANDLE,
    pub guest_mem: *mut c_void,
    pub guest_mem_size: usize,
    pub gdt_table: Option<GdtPointer>,
}

impl Hypervisor for HyperVVm {
    fn create_vm(memory_mb: usize) -> std::io::Result<Self>
    where
        Self: Sized,
    {
        let partition = unsafe { WHvCreatePartition()? };

        let vcpu_count: u32 = 1;
        unsafe {
            WHvSetPartitionProperty(
                partition,
                WHvPartitionPropertyCodeProcessorCount,
                &vcpu_count as *const _ as *const _,
                size_of::<u32>() as u32,
            )?
        };

        unsafe { WHvSetupPartition(partition)? };

        let guest_mem_size = match memory_mb.checked_mul(1024 * 1024) {
            Some(val) => val,
            None => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "Memory allocated too large for architecture",
                ));
            }
        };
        let guest_mem = unsafe {
            VirtualAlloc(
                None,
                guest_mem_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        unsafe {
            WHvMapGpaRange(
                partition,
                guest_mem,
                0x0000,
                guest_mem_size as u64,
                WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute,
            )?
        };

        let vcpu_index: u32 = 0;
        unsafe { WHvCreateVirtualProcessor(partition, vcpu_index, 0)? };

        Ok(HyperVVm {
            partition,
            guest_mem,
            guest_mem_size,
            gdt_table: None,
        })
    }

    fn load_binary(&mut self, data: &[u8], guest_addr: u64) -> std::io::Result<()> {
        let end_addr = guest_addr
            .checked_add(data.len() as u64)
            .ok_or(Error::new(ErrorKind::Other, "Address overflow"))?;
        if self.guest_mem_size < end_addr as usize {
            return Err(Error::new(ErrorKind::Other, "Guest memory underallocated"));
        }

        let start = self.guest_mem as u64 + guest_addr;

        unsafe { copy_nonoverlapping(data.as_ptr(), start as *mut u8, data.len()) };

        Ok(())
    }

    fn setup_gdt(&mut self, guest_gdt_addr: u64, cpu_mode: CpuMode) {
        if cpu_mode == CpuMode::Protected {
            let gdt_table: [GdtEntry; 3] = [
                GdtEntry::new(0, 0, 0, 0),
                GdtEntry::new(0, 0xFFFFF, 0x9A, 0xC),
                GdtEntry::new(0, 0xFFFFF, 0x92, 0xC),
            ];

            let gdt_size = size_of_val(&gdt_table);

            let bytes = unsafe { from_raw_parts(gdt_table.as_ptr() as *const u8, gdt_size) };
            let start = self.guest_mem as u64 + guest_gdt_addr;
            unsafe { copy_nonoverlapping(bytes.as_ptr(), start as *mut u8, bytes.len()); }

            self.gdt_table = Some(GdtPointer {
                limit: (gdt_size - 1) as u16,
                base: guest_gdt_addr,
            });
        } else if cpu_mode == CpuMode::Long {
            // Placeholder
        }
    }

    fn set_entry_point(&mut self, addr: u64, cpu_mode: CpuMode) -> std::io::Result<()> {
        let cs = match cpu_mode {
            CpuMode::Real => WHV_X64_SEGMENT_REGISTER {
                Base: 0,
                Limit: 0xFFFF,
                Selector: 0,
                Anonymous: WHV_X64_SEGMENT_REGISTER_0 { Attributes: 0x9B },
            },
            CpuMode::Protected => WHV_X64_SEGMENT_REGISTER {
                Base: 0,
                Limit: 0xFFFFFFFF,
                Selector: 0x08,
                Anonymous: WHV_X64_SEGMENT_REGISTER_0 { Attributes: 0xC09B },
            },
            // Placeholder, change later
            CpuMode::Long => WHV_X64_SEGMENT_REGISTER {
                Base: 0,
                Limit: 0xFFFF,
                Selector: 0,
                Anonymous: WHV_X64_SEGMENT_REGISTER_0 { Attributes: 0x9B },
            },
        };
        let ds = match cpu_mode {
            CpuMode::Real => WHV_X64_SEGMENT_REGISTER {
                Base: 0,
                Limit: 0xFFFF,
                Selector: 0,
                Anonymous: WHV_X64_SEGMENT_REGISTER_0 { Attributes: 0x93 },
            },
            CpuMode::Protected => WHV_X64_SEGMENT_REGISTER {
                Base: 0,
                Limit: 0xFFFFFFFF,
                Selector: 0x10,
                Anonymous: WHV_X64_SEGMENT_REGISTER_0 { Attributes: 0xC093 },
            },
            // Placeholder, change later
            CpuMode::Long => WHV_X64_SEGMENT_REGISTER {
                Base: 0,
                Limit: 0xFFFF,
                Selector: 0,
                Anonymous: WHV_X64_SEGMENT_REGISTER_0 { Attributes: 0x9B },
            },
        };
        let ss = match cpu_mode {
            CpuMode::Real => WHV_X64_SEGMENT_REGISTER {
                Base: 0,
                Limit: 0xFFFF,
                Selector: 0,
                Anonymous: WHV_X64_SEGMENT_REGISTER_0 { Attributes: 0x93 },
            },
            CpuMode::Protected => WHV_X64_SEGMENT_REGISTER {
                Base: 0,
                Limit: 0xFFFFFFFF,
                Selector: 0x10,
                Anonymous: WHV_X64_SEGMENT_REGISTER_0 { Attributes: 0xC093 },
            },
            // Placeholder, change later
            CpuMode::Long => WHV_X64_SEGMENT_REGISTER {
                Base: 0,
                Limit: 0xFFFF,
                Selector: 0,
                Anonymous: WHV_X64_SEGMENT_REGISTER_0 { Attributes: 0x9B },
            },
        };
        let mut reg_keys = vec![
            WHvX64RegisterRip,
            WHvX64RegisterRflags,
            WHvX64RegisterCs,
            WHvX64RegisterDs,
            WHvX64RegisterSs,
        ];
        let mut reg_values = vec![
            WHV_REGISTER_VALUE { Reg64: addr },
            WHV_REGISTER_VALUE { Reg64: 0x2 },
            WHV_REGISTER_VALUE { Segment: cs },
            WHV_REGISTER_VALUE { Segment: ds },
            WHV_REGISTER_VALUE { Segment: ss },
        ];

        if cpu_mode == CpuMode::Protected {
            reg_keys.push(WHvX64RegisterCr0);
            reg_values.push(WHV_REGISTER_VALUE { Reg64: 0x11 });

            reg_keys.push(WHvX64RegisterGdtr);
            let gdtr = WHV_X64_TABLE_REGISTER {
                Base: (self.gdt_table.as_ref().ok_or_else(|| {
                    Error::new(
                        ErrorKind::Other,
                        "Base field in GDT table not set up correctly",
                    )
                })?)
                .base,
                Limit: (self.gdt_table.as_ref().ok_or_else(|| {
                    Error::new(
                        ErrorKind::Other,
                        "Limit field in GDT table not set up correctly",
                    )
                })?)
                .limit,
                Pad: [0; 3],
            };
            reg_values.push(WHV_REGISTER_VALUE { Table: gdtr });
        } else if cpu_mode == CpuMode::Long {
            // Placeholder
        }

        unsafe {
            WHvSetVirtualProcessorRegisters(
                self.partition,
                0,
                reg_keys.as_ptr(),
                reg_keys.len() as u32,
                reg_values.as_ptr(),
            )?
        };

        Ok(())
    }

    fn run(&mut self) -> ExitReason {
        let mut exit_cx: WHV_RUN_VP_EXIT_CONTEXT = unsafe { mem::zeroed() };
        let exit_cx_size = mem::size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32;

        let run = unsafe {
            WHvRunVirtualProcessor(
                self.partition,
                0,
                &mut exit_cx as *mut _ as *mut _,
                exit_cx_size,
            )
        };

        if let Err(e) = run {
            return ExitReason::Error(format!("WHvRunVirtualProcessor failed {:#?}", e));
        }

        #[allow(non_upper_case_globals)]
        unsafe {
            match exit_cx.ExitReason {
                WHvRunVpExitReasonX64Halt => ExitReason::Halt,
                WHvRunVpExitReasonX64IoPortAccess => {
                    let io = exit_cx.Anonymous.IoPortAccess;
                    let port = io.PortNumber;
                    let size = ((io.AccessInfo.Anonymous._bitfield >> 1) & 0b111) as usize;
                    let is_write = (io.AccessInfo.Anonymous._bitfield & 0b1) != 0;

                    if is_write {
                        let data = (io.Rax as u32).to_le_bytes()[..size].to_vec();

                        let rip = exit_cx.VpContext.Rip as usize;
                        let byte = *((self.guest_mem as *const u8).add(rip) as *const u8);
                        let instruction_len: u64 = match byte {
                            0xEE | 0xEF => 1,
                            0xE6 | 0xE7 => 2,
                            _ => return ExitReason::Error(format!("Unknown IO instruction: {:#x}", byte))
                        };
                        let new_rip = rip as u64 + instruction_len;

                        let rip_key: [WHV_REGISTER_NAME; 1] = [WHvX64RegisterRip];
                        let rip_value: [WHV_REGISTER_VALUE; 1] = [WHV_REGISTER_VALUE { Reg64: new_rip }];
                        if let Err(e) = WHvSetVirtualProcessorRegisters(self.partition, 0, rip_key.as_ptr(), 1, rip_value.as_ptr()) {
                            return ExitReason::Error(format!("WHvSetVirtualProcessorRegisters failed {:#?}", e));
                        }

                        ExitReason::IoOut { port, data }
                    }
                    else {
                        let rip = exit_cx.VpContext.Rip as usize;
                        let byte = *((self.guest_mem as *const u8).add(rip) as *const u8);
                        let instruction_len: u64 = match byte {
                            0xEC | 0xED => 1,
                            0xE4 | 0xE5 => 2,
                            _ => return ExitReason::Error(format!("Unknown IO instruction: {:#x}", byte))
                        };
                        let new_rip = rip as u64 + instruction_len;
                        
                        let rip_key: [WHV_REGISTER_NAME; 1] = [WHvX64RegisterRip];
                        let rip_value: [WHV_REGISTER_VALUE; 1] = [WHV_REGISTER_VALUE { Reg64: new_rip as u64 }];
                        if let Err(e) = WHvSetVirtualProcessorRegisters(self.partition, 0, rip_key.as_ptr(), 1, rip_value.as_ptr()) {
                            return ExitReason::Error(format!("WHvSetVirtualProcessorRegisters failed {:#?}", e));
                        }
                        
                        if port == 0x3FD {
                            let rax_key: [WHV_REGISTER_NAME; 1] = [WHvX64RegisterRax];
                            // Track state on this later instead of just hardcoding 0x20
                            let rax_value: [WHV_REGISTER_VALUE; 1] = [WHV_REGISTER_VALUE { Reg64: 0x20 }];
                            
                            if let Err(e) = WHvSetVirtualProcessorRegisters(self.partition, 0, rax_key.as_ptr(), 1, rax_value.as_ptr()) {
                                return ExitReason::Error(format!("WHvSetVirtualProcessorRegisters failed {:#?}", e));
                            }
                        }
                        
                        ExitReason::IoIn { port, size }
                    }
                }
                WHvRunVpExitReasonUnrecoverableException => ExitReason::Shutdown,
                WHvRunVpExitReasonInvalidVpRegisterValue => ExitReason::FailEntry {
                    hardware_reason: 0,
                    cpu: 0,
                },
                _ => ExitReason::Error(format!("Unhandled WHP exit {:?}", exit_cx.ExitReason)),
            }
        }
    }
}
