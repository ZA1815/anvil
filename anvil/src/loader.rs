use std::{fs::read, io::{self, Error}, path::Path};
use crate::hypervisor::CpuMode;

pub struct LoadedKernel {
    pub entry_point: u64,
    pub segments: Vec<Segment>,
    pub cpu_mode: CpuMode
}

pub struct Segment {
    pub data: Vec<u8>,
    pub guest_addr: u64,
    pub mem_size: u64
}

pub fn parse_kernel<P: AsRef<Path>>(path: P) -> io::Result<LoadedKernel> {
    let kernel = read(path)?;
    
    if kernel[0..4] == [0x7f, b'E', b'L', b'F'] {
        // ELF validity check
        let cpu_mode = match kernel[4] {
            1 => CpuMode::Protected,
            2 => CpuMode::Long,
            _ => return Err(Error::new(io::ErrorKind::Other, "CPU mode not defined"))
        };
        
        if kernel[5] != 1 {
            return Err(Error::new(io::ErrorKind::Other, "Only Little Endianness supported on x86_64"));
        }
        
        if kernel[6] != 1 {
            return Err(Error::new(io::ErrorKind::Other, "ELF version not supported"));
        }
        
        parse_elf(&kernel, cpu_mode)
    }
    else {
        Ok(parse_binary(&kernel))
    }
}

// Guest addr and entry point hardcoded, let user decide later
fn parse_binary(data: &[u8]) -> LoadedKernel {
    let mut vec = Vec::new();
    let binary = Segment { data: data.to_vec(), guest_addr: 0x2000, mem_size: data.len() as u64 };
    vec.push(binary);
    LoadedKernel { entry_point: 0x2000, segments: vec, cpu_mode: CpuMode::Real }
}

fn parse_elf(data: &[u8], cpu_mode: CpuMode) -> io::Result<LoadedKernel> {
    let mut segments = Vec::<Segment>::new();
    if cpu_mode == CpuMode::Protected {
        let entry_point = u32::from_le_bytes(data[0x18..0x1C].try_into().expect("Entry point not found"));
        let pht_offset = u32::from_le_bytes(data[0x1C..0x20].try_into().expect("Program header table offset not found"));
        
        let ph_size = u16::from_le_bytes(data[0x20..0x2C].try_into().expect("Program header table size not found"));
        if ph_size != 32 {
            return Err(Error::new(io::ErrorKind::Other, "Size of program headers are not 32 bytes"));
        }
        
        let ph_num = u16::from_le_bytes(data[0x2C..0x2E].try_into().expect("Number of entries in program header table not found"));
        if ph_num == 0 {
            return Err(Error::new(io::ErrorKind::Other, "Zero program headers in ELF file"));
        }
        
        if pht_offset as usize + (ph_num * ph_size) as usize > data.len() {
            return Err(Error::new(io::ErrorKind::Other, "ELF file is larger than data recieved"));
        }
        
        for i in 0..ph_num {
            let pht_base = pht_offset as usize + (i * ph_size) as usize;
            let ph_type = u32::from_le_bytes(data[pht_base as usize..(pht_base + 0x04) as usize].try_into().expect("Type for program header not found"));
            if ph_type == 1 {
                let ph_offset = u32::from_le_bytes(data[(pht_base + 0x04) as usize..(pht_base + 0x08) as usize].try_into().expect("Flags for program header not found"));
                let ph_vaddr = u32::from_le_bytes(data[(pht_base + 0x08) as usize..(pht_base + 0x0C) as usize].try_into().expect("Offset for program header not found"));
                let ph_paddr = u32::from_le_bytes(data[(pht_base + 0x10) as usize..(pht_base + 0x14) as usize].try_into().expect("Virtual address for program header not found"));
                let ph_filesize = u32::from_le_bytes(data[(pht_base + 0x14) as usize..(pht_base + 0x18) as usize].try_into().expect("Physical address for program header not found"));
                let ph_memsize = u32::from_le_bytes(data[(pht_base + 0x18) as usize..(pht_base + 0x1C) as usize].try_into().expect("File size for program header not found"));
                let ph_flags = u32::from_le_bytes(data[(pht_base + 0x1C) as usize..(pht_base + 0x20) as usize].try_into().expect("Memory size for program header not found"));
                
                if (ph_offset + ph_filesize) as usize > data.len() {
                    return Err(Error::new(io::ErrorKind::Other, "Size of program header file greater than ELF file"));
                }
                if ph_memsize < ph_filesize {
                    return Err(Error::new(io::ErrorKind::Other, "File size larger than memory allocation for program header"));
                }
                if ph_memsize == 0 {
                    return Err(Error::new(io::ErrorKind::Other, "No memory allocated for program header"));
                }
                
                // Add other safety checks later like checking to make sure that entry is in at least one program header
                
                let data_exec = &data[ph_offset as usize..(ph_offset + ph_filesize) as usize];
                
                segments.push(Segment { data: data_exec.to_vec(), guest_addr: ph_vaddr as u64, mem_size: ph_memsize as u64 });
            }
        }
        
        
        Ok(LoadedKernel { entry_point: entry_point as u64, segments, cpu_mode })
    }
    else {
        let entry_point = u64::from_le_bytes(data[0x18..0x20].try_into().expect("Entry point not found"));
        let pht_offset = u64::from_le_bytes(data[0x20..0x28].try_into().expect("Program header table offset not found"));
        
        let ph_size = u16::from_le_bytes(data[0x36..0x38].try_into().expect("Program header table size not found"));
        if ph_size != 56 {
            return Err(Error::new(io::ErrorKind::Other, "Size of program headers are not 56 bytes"));
        }
        
        let ph_num = u16::from_le_bytes(data[0x38..0x3A].try_into().expect("Number of entries in program header table not found"));
        if ph_num == 0 {
            return Err(Error::new(io::ErrorKind::Other, "Zero program headers in ELF file"));
        }
        
        if pht_offset + (ph_num * ph_size) as u64 > data.len() as u64 {
            return Err(Error::new(io::ErrorKind::Other, "ELF file is larger than data recieved"));
        }
        
        for i in 0..ph_num {
            let pht_base = pht_offset + (i * ph_size) as u64;
            let ph_type = u32::from_le_bytes(data[pht_base as usize..(pht_base + 0x04) as usize].try_into().expect("Type for program header not found"));
            if ph_type == 1 {
                let ph_flags = u32::from_le_bytes(data[(pht_base + 0x04) as usize..(pht_base + 0x08) as usize].try_into().expect("Flags for program header not found"));
                let ph_offset = u64::from_le_bytes(data[(pht_base + 0x08) as usize..(pht_base + 0x10) as usize].try_into().expect("Offset for program header not found"));
                let ph_vaddr = u64::from_le_bytes(data[(pht_base + 0x10) as usize..(pht_base + 0x18) as usize].try_into().expect("Virtual address for program header not found"));
                let ph_paddr = u64::from_le_bytes(data[(pht_base + 0x18) as usize..(pht_base + 0x20) as usize].try_into().expect("Physical address for program header not found"));
                let ph_filesize = u64::from_le_bytes(data[(pht_base + 0x20) as usize..(pht_base + 0x28) as usize].try_into().expect("File size for program header not found"));
                let ph_memsize = u64::from_le_bytes(data[(pht_base + 0x28) as usize..(pht_base + 0x30) as usize].try_into().expect("Memory size for program header not found"));
                
                if ph_offset + ph_filesize > data.len() as u64 {
                    return Err(Error::new(io::ErrorKind::Other, "Size of program header file greater than ELF file"));
                }
                if ph_memsize < ph_filesize {
                    return Err(Error::new(io::ErrorKind::Other, "File size larger than memory allocation for program header"));
                }
                if ph_memsize == 0 {
                    return Err(Error::new(io::ErrorKind::Other, "No memory allocated for program header"));
                }
                
                // Add other safety checks later like checking to make sure that entry is in at least one program header
                
                let data_exec = &data[ph_offset as usize..(ph_offset + ph_filesize) as usize];
                
                segments.push(Segment { data: data_exec.to_vec(), guest_addr: ph_vaddr, mem_size: ph_memsize });
            }
        }
        
        Ok(LoadedKernel { entry_point, segments, cpu_mode })
    }
}