use clap::Parser;
use clap::{arg, Arg, ArgAction, Command, Subcommand};
use elf::endian::AnyEndian;
use elf::note::Note;
use elf::note::NoteGnuBuildId;
use elf::section::SectionHeader;
use elf::ElfBytes;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::str::FromStr;

/*fn int_with_base_type(val: &str) -> i64 {
    i64::from_str_radix(val, 0).unwrap()
}

fn try_parse_int(x: &str, base: u32) -> Option<i64> {
    i64::from_str_radix(x, base).ok()
}

fn align_up(x: u64, alignment: u64) -> u64 {
    (x + (alignment - 1)) & !(alignment - 1)
}

fn align_down(x: u64, alignment: u64) -> u64 {
    x & !(alignment - 1)
}

fn ilog2(x: u64) -> u64 {
    if x <= 0 {
        panic!("math domain error");
    }
    (64 - x.leading_zeros()) - 1
}

fn is_intervals_overlap(p1: (u64, u64), p2: (u64, u64)) -> bool {
    p1.0 <= p2.1 && p1.1 <= p2.0
}

fn check_file_magic(f: &mut File, expected_magic: &[u8]) -> bool {
    let mut magic = vec![0; expected_magic.len()];
    let old_offset = f.metadata().unwrap().len();
    f.read_exact(&mut magic).unwrap();
    f.seek(std::io::SeekFrom::Start(old_offset)).unwrap();
    magic == expected_magic
}

fn parse_version(version: u16) -> String {
    let major = 10 * (version >> 12) + ((version >> 8) & 0xF);
    let minor = 10 * ((version >> 4) & 0xF) + (version & 0xF);
    format!("{0}.{1:02}.{2:03}", major, minor, 0) // FIXME: Patch version
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.input(data);
    let mut output = vec![0u8; hasher.output_bytes()];
    hasher.result(&mut output);
    output
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::new(Sha256::new(), key);
    hmac.input(data);
    let mut output = vec![0u8; hmac.output_bytes()];
    hmac.raw_result(&mut output);
    output
}

#[derive(Debug)]
struct ElfError {
    msg: String,
}

impl ElfError {
    fn new(msg: &str) -> ElfError {
        ElfError {
            msg: msg.to_string(),
        }
    }
}

const ELF_MAGIC: &[u8; 4] = b"\x7FELF";

struct ElfEHdr {
    magic: [u8; 4],
    machine_class: u8,
    data_encoding: u8,
    version: u8,
    os_abi: u8,
    abi_version: u8,
    nident_size: u8,
    elf_type: u16,
    machine: u16,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstridx: u16,
}

impl ElfEHdr {
    const CLASS64: u8 = 2;
    const DATA2LSB: u8 = 1;
    const EM_X86_64: u16 = 62;
    const EV_CURRENT: u8 = 1;
    const ET_EXEC: u16 = 2;
    const ET_SCE_EXEC: u16 = 65024;
    const ET_SCE_EXEC_ASLR: u16 = 65104;
    const ET_SCE_DYNAMIC: u16 = 65112;

    fn new() -> Self {
        Self {
            magic: *ELF_MAGIC,
            machine_class: 0,
            data_encoding: 0,
            version: 0,
            os_abi: 0,
            abi_version: 0,
            nident_size: 0,
            elf_type: 0,
            machine: 0,
            entry: 0,
            phoff: 0,
            shoff: 0,
            flags: 0,
            ehsize: 0,
            phentsize: 0,
            phnum: 0,
            shentsize: 0,
            shnum: 0,
            shstridx: 0,
        }
    }

    fn load(&mut self, f: &mut File) -> Result<(), String> {
        let mut header_bytes = [0u8; 48];
        f.read_exact(&mut header_bytes).map_err(|e| e.to_string())?;
        let mut cursor = std::io::Cursor::new(header_bytes);

        self.magic = cursor
            .get_mut()
            .read_exact(4)
            .try_into()
            .map_err(|e| e.to_string())?;
        self.machine_class = cursor.get_mut().read_u8().map_err(|e| e.to_string())?;
        self.data_encoding = cursor.get_mut().read_u8().map_err(|e| e.to_string())?;
        self.version = cursor.get_mut().read_u8().map_err(|e| e.to_string())?;
        self.os_abi = cursor.get_mut().read_u8().map_err(|e| e.to_string())?;
        self.abi_version = cursor.get_mut().read_u8().map_err(|e| e.to_string())?;
        self.nident_size = cursor.get_mut().read_u8().map_err(|e| e.to_string())?;
        self.elf_type = cursor
            .get_mut()
            .read_u16::<u16>()
            .map_err(|e| e.to_string())?;
        self.machine = cursor
            .get_mut()
            .read_u16::<u16>()
            .map_err(|e| e.to_string())?;
        self.entry = cursor
            .get_mut()
            .read_u64::<u64>()
            .map_err(|e| e.to_string())?;
        self.phoff = cursor
            .get_mut()
            .read_u64::<u64>()
            .map_err(|e| e.to_string())?;
        self.shoff = cursor
            .get_mut()
            .read_u64::<u64>()
            .map_err(|e| e.to_string())?;
        self.flags = cursor
            .get_mut()
            .read_u32::<u32>()
            .map_err(|e| e.to_string())?;
        self.ehsize = cursor
            .get_mut()
            .read_u16::<u16>()
            .map_err(|e| e.to_string())?;
        self.phentsize = cursor
            .get_mut()
            .read_u16::<u16>()
            .map_err(|e| e.to_string())?;
        self.phnum = cursor
            .get_mut()
            .read_u16::<u16>()
            .map_err(|e| e.to_string())?;
        self.shentsize = cursor
            .get_mut()
            .read_u16::<u16>()
            .map_err(|e| e.to_string())?;
        self.shnum = cursor
            .get_mut()
            .read_u16::<u16>()
            .map_err(|e| e.to_string())?;
        self.shstridx = cursor
            .get_mut()
            .read_u16::<u16>()
            .map_err(|e| e.to_string())?;

        if self.magic != *ELF_MAGIC
            || self.machine_class != Self::CLASS64
            || self.data_encoding != Self::DATA2LSB
        {
            return Err("Unsupported class or data encoding.".to_string());
        }

        if self.machine != Self::EM_X86_64 || self.version != Self::EV_CURRENT {
            return Err("Unsupported machine type or version.".to_string());
        }

        if self.phentsize != 0
            || (self.shentsize > 0 && self.shentsize != std::mem::size_of::<ElfPHdr>() as u16)
        {
            return Err("Unsupported header entry size.".to_string());
        }

        if ![
            Self::ET_EXEC,
            Self::ET_SCE_EXEC,
            Self::ET_SCE_EXEC_ASLR,
            Self::ET_SCE_DYNAMIC,
        ]
        .contains(&self.elf_type)
        {
            return Err("Unsupported type.".to_string());
        }

        Ok(())
    }

    fn save(&self, f: &mut File) -> Result<(), String> {
        f.write(&self.magic).map_err(|e| e.to_string())?;
        f.write_u8(self.machine_class).map_err(|e| e.to_string())?;
        f.write_u8(self.data_encoding).map_err(|e| e.to_string())?;
        f.write_u8(self.version).map_err(|e| e.to_string())?;
        f.write_u8(self.os_abi).map_err(|e| e.to_string())?;
        f.write_u8(self.abi_version).map_err(|e| e.to_string())?;
        f.write_u8(self.nident_size).map_err(|e| e.to_string())?;
        f.write_u16::<u16>(self.elf_type)
            .map_err(|e| e.to_string())?;
        f.write_u16::<u16>(self.machine)
            .map_err(|e| e.to_string())?;
        f.write_u64::<u64>(self.entry).map_err(|e| e.to_string())?;
        f.write_u64::<u64>(self.phoff).map_err(|e| e.to_string())?;
        f.write_u64::<u64>(self.shoff).map_err(|e| e.to_string())?;
        f.write_u32::<u32>(self.flags).map_err(|e| e.to.string())?;
        f.write_u16::<u16>(self.ehsize).map_err(|e| e.to_string())?;
        f.write_u16::<u16>(self.phentsize)
            .map_err(|e| e.to.string())?;
        f.write_u16::<u16>(self.phnum).map_err(|e| e.to_string())?;
        f.write_u16::<u16>(self.shentsize)
            .map_err(|e| e.to_string())?;
        f.write_u16::<u16>(self.shnum).map_err(|e| e.to_string())?;
        f.write_u16::<u16>(self.shstridx)
            .map_err(|e| e.to.string())?;

        Ok(())
    }

    fn has_segments(&self) -> bool {
        self.phentsize > 0 && self.phnum > 0
    }

    fn has_sections(&self) -> bool {
        self.shentsize > 0 && self.shnum > 0
    }
}

struct ElfPHdr {
    elf_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

impl ElfPHdr {
    const PT_LOAD: u32 = 1;
    const PT_DYNAMIC: u32 = 2;
    const PT_INTERP: u32 = 3;
    const PT_TLS: u32 = 7;
    const PT_GNU_EH_FRAME: u32 = 2151947632;
    const PT_GNU_STACK: u32 = 2151947633;
    const PT_SCE_RELA: u32 = 1610612736;
    const PT_SCE_DYNLIBDATA: u32 = 1635778560;
    const PT_SCE_PROCPARAM: u32 = 1635778561;
    const PT_SCE_MODULE_PARAM: u32 = 1635778562;
    const PT_SCE_RELRO: u32 = 1635782144;
    const PT_SCE_COMMENT: u32 = 1879048192;
    const PT_SCE_VERSION: u32 = 1879048193;

    fn new() -> Self {
        Self {
            elf_type: 0,
            flags: 0,
            offset: 0,
            vaddr: 0,
            paddr: 0,
            filesz: 0,
            memsz: 0,
            align: 0,
        }
    }

    fn load(&mut self, f: &mut File) -> Result<(), String> {
        let mut header_bytes = [0u8; 56];
        f.read_exact(&mut header_bytes).map_err(|e| e.to_string())?;
        let mut cursor = std::io::Cursor::new(header_bytes);

        self.elf_type = cursor
            .get_mut()
            .read_u32::<u32>()
            .map_err(|e| e.to_string())?;
        self.flags = cursor
            .get_mut()
            .read_u32::<u32>()
            .map_err(|e| e.to.string())?;
        self.offset = cursor
            .get_mut()
            .read_u64::<u64>()
            .map_err(|e| e.to_string())?;
        self.vaddr = cursor
            .get_mut()
            .read_u64::<u64>()
            .map_err(|e| e.to_string())?;
        self.paddr = cursor
            .get_mut()
            .read_u64::<u64>()
            .map_err(|e| e.to_string())?;
        self.filesz = cursor
            .get_mut()
            .read_u64::<u64>()
            .map_err(|e| e.to_string())?;
        self.memsz = cursor
            .get_mut()
            .read_u64::<u64>()
            .map_err(|e| e.to_string())?;
        self.align = cursor
            .get_mut()
            .read_u64::<u64>()
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    fn save(&self, f: &mut File) -> Result<(), String> {
        f.write_u32::<u32>(self.elf_type)
            .map_err(|e| e.to_string())?;
        f.write_u32::<u32>(self.flags).map_err(|e| e.to.string())?;
        f.write_u64::<u64>(self.offset).map_err(|e| e.to_string())?;
        f.write_u64::<u64>(self.vaddr).map_err(|e| e.to_string())?;
        f.write_u64::<u64>(self.paddr).map_err(|e| e.to.string())?;
        f.write_u64::<u64>(self.filesz).map_err(|e| e.to_string())?;
        f.write_u64::<u64>(self.memsz).map_err(|e| e.to.string())?;
        f.write_u64::<u64>(self.align).map_err(|e| e.to.string())?;

        Ok(())
    }

    fn name(&self) -> &str {
        match self.elf_type {
            Self::PT_LOAD => {
                if self.flags == (Self::PF_READ_EXEC) {
                    ".text"
                } else if self.flags == (Self::PF_READ_WRITE) {
                    ".data"
                } else {
                    &format!(".load_{:02}", self.elf_type)
                }
            }
            Self::PT_DYNAMIC => ".dynamic",
            Self::PT_INTERP => ".interp",
            Self::PT_TLS => ".tls",
            Self::PT_GNU_EH_FRAME => ".eh_frame_hdr",
            Self::PT_SCE_DYNLIBDATA => ".sce_dynlib_data",
            Self::PT_SCE_PROCPARAM => ".sce_process_param",
            Self::PT_SCE_MODULE_PARAM => ".sce_module_param",
            Self::PT_SCE_COMMENT => ".sce_comment",
            _ => "",
        }
    }

    fn class_name(&self) -> &str {
        if self.flags == Self::PF_READ_EXEC {
            "CODE"
        } else {
            "DATA"
        }
    }
}

const ELF_SHDR_FMT_SIZE: usize = 64;

struct ElfSHdr {
    name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

impl ElfSHdr {
    fn new() -> Self {
        Self {
            name: 0,
            sh_type: 0,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: 0,
            sh_size: 0,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
        }
    }

    fn load(&mut self, f: &mut File) -> Result<(), String> {
        let mut header_bytes = [0u8; ELF_SHDR_FMT_SIZE];
        f.read_exact(&mut header_bytes).map_err(|e| e.to_string())?;
        let mut cursor = std::io::Cursor::new(header_bytes);

        self.name = cursor.get_mut().read_u32::<u32>().map_err(|e| e.to_string())?;
        self.sh_type = cursor.get_mut().read_u32::<u32>().map_err(|e| e.to_string())?;
        self.sh_flags = cursor.get_mut().read_u64::<u64>().map_err(|e| e.to_string())?;
        self.sh_addr = cursor.get_mut().read_u64::<u64>().map_err(|e| e.to.string())?;
        self.sh_offset = cursor.get_mut().read_u64::<u64>().map_err(|e| e.to.string())?;
        self.sh_size = cursor.get_mut().read_u64::<u64>().map_err(|e| e.to_string())?;
        self.sh_link = cursor.get_mut().read_u32::<u32>().map_err(|e| e.to_string())?;
        self.sh_info = cursor.get_mut().read_u32::<u32>().map_err(|e| e.to_string())?;
        self.sh_addralign = cursor.get_mut().read_u64::<u64>().map_err(|e| e.to.string())?;
        self.sh_entsize = cursor.get_mut().read_u64::<u64>().map_err(|e| e.to_string())?;

        Ok(())
    }

    fn save(&self, f: &mut File) -> Result<(), String> {
        f.write_u32::<u32>(self.name).map_err(|e| e.to_string())?;
        f.write_u32::<u32>(self.sh_type).map_err(|e| e.to_string())?;
        f.write_u64::<u64>(self.sh_flags).map_err(|e| e.to_string())?;
        f.write_u64::<u64>(self.sh_addr).map_err(|e| e.to_string())?;
        f.write_u64::<u64>(self.sh_offset).map_err(|e| e.to.string())?;
        f.write_u64::<u64>(self.sh_size).map_err(|e| e.to.string())?;
        f.write_u32::<u32>(self.sh_link).map_err(|e| e.to_string())?;
        f.write_u32::<u32>(self.sh_info).map_err(|e| e.to_string())?;
        f.write_u64::<u64>(self.sh_addralign).map_err(|e| e.to.string())?;
        f.write_u64::<u64>(self.sh_entsize).map_err(|e| e.to_string())?;

        Ok(())
    }
}

struct ElfFile {
    ehdr: ElfEHdr,
    phdrs: Vec<ElfPHdr>,
    shdrs: Vec<ElfSHdr>,
    file_size: usize,
    digest: Vec<u8>,
    segments: Vec<Vec<u8>>,
    sections: Vec<Vec<u8>,
    ignore_shdrs: bool,
}

impl ElfFile {
    fn new(ignore_shdrs: bool) -> Self {
        Self {
            ehdr: ElfEHdr::new(),
            phdrs: vec![],
            shdrs: vec![],
            file_size: 0,
            digest: vec![],
            segments: vec![],
            sections: vec![],
            ignore_shdrs,
        }
    }

    fn load(&mut self, f: &mut File) -> Result<(), String> {
        let start_offset = f.seek(std::io::SeekFrom::Current(0)).map_err(|e| e.to_string())?;
        let mut data = vec![];
        f.read_to_end(&mut data).map_err(|e| e.to_string())?;
        self.file_size = data.len();
        self.digest = sha256(&data);

        f.seek(std::io::SeekFrom::Start(start_offset)).map_err(|e| e.to_string())?;

        self.ehdr = ElfEHdr::new();
        self.ehdr.load(f)?;

        if self.ignore_shdrs {
            self.ehdr.shnum = 0;
        }

        self.phdrs = vec![];
        self.segments = vec![];
        if self.ehdr.has_segments() {
            for i in 0..self.ehdr.phnum {
                f.seek(std::io::SeekFrom::Start(start_offset + self.ehdr.phoff + i as u64 * self.ehdr.phentsize as u64))
                    .map_err(|e| e.to_string())?;
                let mut phdr = ElfPHdr::new(i);
                phdr.load(f)?;
                self.phdrs.push(phdr.clone());
                if phdr.filesz > 0 {
                    f.seek(std::io::SeekFrom::Start(start_offset + phdr.offset)).map_err(|e| e.to_string())?;
                    let mut phdr_data = vec![0u8; phdr.filesz as usize];
                    f.read_exact(&mut phdr_data).map_err(|e| e.to_string())?;
                    self.segments.push(phdr_data);
                }
            }
        }

        self.shdrs = vec![];
        self.sections = vec![];
        if self.ehdr.has_sections() {
            for i in 0..self.ehdr.shnum {
                f.seek(std::io::SeekFrom::Start(start_offset + self.ehdr.shoff + i as u64 * self.ehdr.shentsize as u64))
                    .map_err(|e| e.to_string())?;
                let mut shdr = ElfSHdr::new();
                shdr.load(f)?;
                self.shdrs.push(shdr.clone());
                if shdr.sh_size > 0 {
                    f.seek(std::io::SeekFrom::Start(start_offset + shdr.sh_offset)).map_err(|e| e.to.string())?;
                    let mut shdr_data = vec![0u8; shdr.sh_size as usize];
                    f.read_exact(&mut shdr_data).map_err(|e| e.to_string())?;
                    self.sections.push(shdr_data);
                }
            }
        }

        Ok(())
    }

    fn save(&self, f: &mut File, no_sections: bool) -> Result<(), String> {
        let start_offset = f.seek(std::io::SeekFrom::Current(0)).map_err(|e| e.to_string())?;

        self.ehdr.save(f)?;

        if !no_sections && self.ehdr.has_sections() {
            for i in 0..self.ehdr.shnum {
                f.seek(std::io::SeekFrom::Start(start_offset + self.ehdr.shoff + i as u64 * self.ehdr.shentsize as u64))
                    .map_err(|e| e.to_string())?;
                self.shdrs[i].save(f);
            }
        }

        if self.ehdr.has_segments() {
            for i in 0..self.ehdr.phnum {
                f.seek(std::io::SeekFrom::Start(start_offset + self.ehdr.phoff + i as u64 * self.ehdr.phentsize as u64))
                    .map_err(|e| e.to_string())?;
                self.phdrs[i].save(f);
            }
        }

        Ok(())
    }
}

const DIGEST_SIZE: usize = 0x20;
const SIGNATURE_SIZE: usize = 0x100;
const BLOCK_SIZE: usize = 0x4000;
const DEFAULT_BLOCK_SIZE: usize = 0x1000;

const SELF_CONTROL_BLOCK_TYPE_NPDRM: u16 = 0x3;
const SELF_NPDRM_CONTROL_BLOCK_CONTENT_ID_SIZE: usize = 0x13;
const SELF_NPDRM_CONTROL_BLOCK_RANDOM_PAD_SIZE: usize = 0xD;

const EMPTY_DIGEST: [u8; DIGEST_SIZE] = [0; DIGEST_SIZE];
const EMPTY_SIGNATURE: [u8; SIGNATURE_SIZE] = [0; SIGNATURE_SIZE];

struct SignedElfEntry {
    props: u64,
    offset: u64,
    filesz: u64,
    memsz: u64,
}

impl SignedElfEntry {
    const FMT: &'static str = "<4Q";

    fn new() -> Self {
        Self {
            props: 0,
            offset: 0,
            filesz: 0,
            memsz: 0,
        }
    }

    fn save(&self, f: &mut std::fs::File) -> Result<(), std::io::Error> {
        let data = [
            self.props.to_le_bytes(),
            self.offset.to_le_bytes(),
            self.filesz.to_le_bytes(),
            self.memsz.to_le_bytes(),
        ]
        .concat();
        f.write_all(&data)
    }

    fn order(&self) -> u64 {
        (self.props >> 0) & 0x1
    }

    fn set_order(&mut self, value: u64) {
        self.props &= !(0x1 << 0);
        self.props |= (value & 0x1) << 0;
    }

    fn encrypted(&self) -> bool {
        ((self.props >> 1) & 0x1) != 0
    }

    fn set_encrypted(&mut self, value: bool) {
        self.props &= !(0x1 << 1);
        if value {
            self.props |= (0x1 << 1);
        }
    }

    fn signed(&self) -> bool {
        ((self.props >> 2) & 0x1) != 0
    }

    fn set_signed(&mut self, value: bool) {
        self.props &= !(0x1 << 2);
        if value {
            self.props |= (0x1 << 2);
        }
    }

    fn compressed(&self) -> bool {
        ((self.props >> 3) & 0x1) != 0
    }

    fn set_compressed(&mut self, value: bool) {
        self.props &= !(0x1 << 3);
        if value {
            self.props |= (0x1 << 3);
        }
    }

    fn has_blocks(&self) -> bool {
        ((self.props >> 8) & 0x1) != 0
    }

    fn set_has_blocks(&mut self, value: bool) {
        self.props &= !(0x1 << 8);
        if value {
            self.props |= (0x1 << 8);
        }
    }

    fn has_digests(&self) -> bool {
        ((self.props >> 11) & 0x1) != 0
    }

    fn set_has_digests(&mut self, value: bool) {
        self.props &= !(0x1 << 11);
        if value {
            self.props |= (0x1 << 11);
        }
    }

    fn has_extents(&self) -> bool {
        ((self.props >> 12) & 0x1) != 0
    }

    fn set_has_extents(&mut self, value: bool) {
        self.props &= !(0x1 << 12);
        if value {
            self.props |= (0x1 << 12);
        }
    }

    fn has_meta_segment(&self) -> bool {
        ((self.props >> 15) & 0x1) != 0
    }

    fn set_has_meta_segment(&mut self, value: bool) {
        self.props &= !(0x1 << 15);
        if value {
            self.props |= (0x1 << 15);
        }
    }

    fn wbits(&self) -> u64 {
        (self.props >> 16) & 0x7
    }

    fn set_wbits(&mut self, value: u64) {
        self.props &= !(0x7 << 16);
        self.props |= (value & 0x7) << 16;
    }

    fn block_size(&self) -> usize {
        if self.has_blocks() {
            1 << (12 + ((self.props >> 20) & 0xF))
        } else {
            DEFAULT_BLOCK_SIZE
        }
    }

    fn set_block_size(&mut self, value: usize) {
        self.props &= !(0xF << 20);
        if self.has_blocks() {
            let value = ilog2(value) - 12;
            self.props |= (value as u64 & 0xF) << 20;
        } else {
            self.props |= (0 as u64 & 0xF) << 20; // TODO: check
        }
    }

    fn segment_index(&self) -> u64 {
        (self.props >> 20) & 0xFFFF
    }

    fn set_segment_index(&mut self, value: u64) {
        self.props &= !(0xFFFF << 20);
        self.props |= (value & 0xFFFF) << 20;
    }

    fn is_meta_segment(&self) -> bool {
        (self.props & 0xF0000) != 0
    }
}

struct SignedElfExInfo {
    paid: u64,
    ptype: u64,
    app_version: [u8; 32],
    fw_version: [u8; 13],
    digest: [u8; DIGEST_SIZE],
}

impl SignedElfExInfo {
    const FMT: &'static str = "<4Q32s";

    fn new() -> Self {
        Self {
            paid: 0,
            ptype: 0,
            app_version: [0; 32],
            fw_version: [0; 13],
            digest: [0; DIGEST_SIZE],
        }
    }

    fn save(&self, f: &mut std::fs::File) -> Result<(), std::io::Error> {
        let data = [
            self.paid.to_le_bytes(),
            self.ptype.to_le_bytes(),
            self.app_version.to_vec(),
            self.fw_version.to_vec(),
            self.digest.to_vec(),
        ]
        .concat();
        f.write_all(&data)
    }
}

struct SignedElfNpdrmControlBlock {
    _type: u16,
    content_id: [u8; SELF_NPDRM_CONTROL_BLOCK_CONTENT_ID_SIZE],
    random_pad: [u8; SELF_NPDRM_CONTROL_BLOCK_RANDOM_PAD_SIZE],
}

impl SignedElfNpdrmControlBlock {
    const FMT: &'static str = "<H14x19s13s";

    fn new() -> Self {
        Self {
            _type: SELF_CONTROL_BLOCK_TYPE_NPDRM,
            content_id: [0; SELF_NPDRM_CONTROL_BLOCK_CONTENT_ID_SIZE],
            random_pad: [0; SELF_NPDRM_CONTROL_BLOCK_RANDOM_PAD_SIZE],
        }
    }

    fn save(&self, f: &mut std::fs::File) -> Result<(), std::io::Error> {
        let data = [
            self._type.to_le_bytes(),
            [0; 14].to_vec(),
            self.content_id.to_vec(),
            self.random_pad.to_vec(),
        ]
        .concat();
        f.write_all(&data)
    }
}

struct SignedElfMetaBlock;

impl SignedElfMetaBlock {
    const FMT: &'static str = "<80x";

    fn new() -> Self {
        Self
    }

    fn save(&self, f: &mut std::fs::File) -> Result<(), std::io::Error> {
        let data = [0; 80];
        f.write_all(&data)
    }
}

struct SignedElfMetaFooter {
    unk1: u32,
}

impl SignedElfMetaFooter {
    const FMT: &'static str = "<48xI28x";

    fn new() -> Self {
        Self { unk1: 0 }
    }

    fn save(&self, f: &mut std::fs::File) -> Result<(), std::io::Error> {
        let data = [
            [0; 48].to_vec(),
            self.unk1.to_le_bytes().to_vec(),
            [0; 28].to_vec(),
        ]
        .concat();
        f.write_all(&data)
    }
}

fn ilog2(x: usize) -> u64 {
    if x <= 0 {
        panic!("math domain error");
    }
    ((64 - x.leading_zeros()) - 1) as u64
}

const MAGIC: [u8; 4] = [0x4F, 0x15, 0x3D, 0x1D];
const VERSION: u8 = 0x00;
const MODE: u8 = 0x01;
const ENDIAN: u8 = 0x01;
const ATTRIBS: u8 = 0x12;
const KEY_TYPE: u16 = 0x101;
const FLAGS_SEGMENT_SIGNED_SHIFT: u64 = 4;
const FLAGS_SEGMENT_SIGNED_MASK: u64 = 0x7;
const HAS_NPDRM: bool = true;

struct SignedElfFile<'a> {
    elf: &'a ElfFile,
    magic: [u8; 4],
    version: u8,
    mode: u8,
    endian: u8,
    attribs: u8,
    key_type: u16,
    header_size: u64,
    meta_size: u64,
    file_size: u64,
    num_entries: u64,
    flags: u64,
    entries: Vec<SignedElfEntry>,
    ex_info: SignedElfExInfo,
    npdrm_control_block: Option<SignedElfNpdrmControlBlock>,
    meta_blocks: Vec<SignedElfMetaBlock>,
    meta_footer: SignedElfMetaFooter,
    signature: [u8; SIGNATURE_SIZE],
    version_data: Option<Vec<u8>>,
    paid: u64,
    ptype: u64,
    app_version: [u8; 32],
    fw_version: [u8; 13],
    auth_info: Option<Vec<u8>>,
}

impl<'a> SignedElfFile<'a> {
    fn new(elf: &'a ElfFile, paid: u64, ptype: u64, app_version: [u8; 32], fw_version: [u8; 13], auth_info: Option<Vec<u8>>) -> Self {
        let magic = MAGIC;
        let version = VERSION;
        let mode = MODE;
        let endian = ENDIAN;
        let attribs = ATTRIBS;
        let key_type = KEY_TYPE;
        let flags = 0x2; // Adjust this value as needed
        let mut entries = Vec::new();
        let mut meta_blocks = Vec::new();
        let meta_footer = SignedElfMetaFooter { unk1: 0x10000 };
        let signature = [0; SIGNATURE_SIZE];
        let version_data = None;
        let npdrm_control_block = if HAS_NPDRM {
            Some(SignedElfNpdrmControlBlock {
                _type: SELF_CONTROL_BLOCK_TYPE_NPDRM,
                content_id: [0; SELF_NPDRM_CONTROL_BLOCK_CONTENT_ID_SIZE],
                random_pad: [0; SELF_NPDRM_CONTROL_BLOCK_RANDOM_PAD_SIZE],
            })
        } else {
            None
        };

        Self {
            elf,
            magic,
            version,
            mode,
            endian,
            attribs,
            key_type,
            header_size: 0,
            meta_size: 0,
            file_size: 0,
            num_entries: 0,
            flags,
            entries,
            ex_info: SignedElfExInfo {
                paid,
                ptype,
                app_version,
                fw_version,
                digest: [0; DIGEST_SIZE],
            },
            npdrm_control_block,
            meta_blocks,
            meta_footer,
            signature,
            version_data,
            paid,
            ptype,
            app_version,
            fw_version,
            auth_info,
        }
    }

    fn _prepare(&mut self) {
        // Calculate necessary fields and populate data
        // ...

        // Example logic for calculating header_size and meta_size
        // self.header_size = ...;
        // self.meta_size = ...;
        // ...

        // Initialize entries, meta_blocks, and ex_info
        // ...

        // Generate or load version_data
        // ...

        // Calculate file_size based on header_size and meta_size
        self.file_size = self.header_size + self.meta_size;

        // Calculate signature
        // ...
    }

    fn save(&mut self, f: &mut File) -> Result<(), std::io::Error> {
        let start_offset = f.seek(std::io::SeekFrom::Current(0))?;

        // Calculate necessary fields
        self._prepare();

        // Write common header
        f.write_all(&self.magic)?;
        f.write(&[self.version, self.mode, self.endian, self.attribs])?;

        // Write extended header
        f.write_all(&self.key_type.to_le_bytes())?;
        f.write_all(&self.header_size.to_le_bytes())?;
        f.write_all(&self.meta_size.to_le_bytes())?;
        f.write_all(&self.file_size.to_le_bytes())?;
        f.write_all(&self.num_entries.to_le_bytes())?;
        f.write_all(&self.flags.to_le_bytes())?;

        // Write entries
        for entry in self.entries.iter() {
            entry.save(f)?;
        }

        // Write ELF headers
        // ...

        // Write extended info
        self.ex_info.save(f)?;

        // Write NPDRM control block
        if let Some(npdrm_control_block) = &self.npdrm_control_block {
            npdrm_control_block.save(f)?;
        }

        // Write meta blocks
        for meta_block in self.meta_blocks.iter() {
            meta_block.save(f)?;
        }

        // Write meta footer
        self.meta_footer.save(f)?;

        // Write signature
        f.write(&self.signature)?;

        // Write segments
        // ...

        // Write version data
        if let Some(version_data) = &self.version_data {
            f.write(version_data)?;
        }

        // Adjust the file pointer
        f.seek(std::io::SeekFrom::Start(start_offset))?;

        Ok(())
    }
}

const SELF_NPDRM_CONTROL_BLOCK_CONTENT_ID_SIZE: usize = 19;
const SELF_NPDRM_CONTROL_BLOCK_RANDOM_PAD_SIZE: usize = 13;

fn ensure_hex_string(val: &str, exact_size: Option<usize>, min_size: Option<usize>, max_size: Option<usize>) -> Result<Vec<u8>, ParseIntError> {
    let val = val.replace(" ", "");
    let val_size = val.len();

    let mut val = if val_size > 0 {
        if val.starts_with("0x") || val.starts_with("0X") {
            val[2..].to_string()
        } else {
            val.to_string()
        }
    } else {
        val.to_string()
    };

    let val_size = val.len();

    if val_size % 2 != 0 || !val.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ParseIntError {});
    }

    let mut val_bytes = Vec::new();
    for i in (0..val_size).step_by(2) {
        val_bytes.push(u8::from_str_radix(&val[i..i+2], 16)?);
    }

    if let Some(size) = exact_size {
        if val_bytes.len() != size {
            return Err(ParseIntError {});
        }
    } else {
        if let Some(min) = min_size {
            if val_bytes.len() < min {
                return Err(ParseIntError {});
            }
        }
        if let Some(max) = max_size {
            if val_bytes.len() > max {
                return Err(ParseIntError {});
            }
        }
    }

    Ok(val_bytes)
}

fn input_file_type(val: &str) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(val);
    if !path.exists() || !path.is_file() {
        return Err("invalid input file");
    }
    Ok(path)
}

fn output_file_type(val: &str) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(val);
    if path.exists() && (!path.is_file() || !path.metadata().unwrap().permissions().readonly()) {
        return Err("invalid output file");
    }
    Ok(path)
}

fn auth_info_type(val: &str) -> Result<Vec<u8>, ParseIntError> {
    let new_val = ensure_hex_string(val, Some(0x88), None, None)?;
    Ok(new_val)
}*/

fn cli() -> Command {
    Command::new("make_fself")
        .about("Fake Signed Elf Maker")
        .version("0.1")
        .arg_required_else_help(true)
        .author("TheRouLetteBoi")
        .subcommand(
            Command::new("input")
                .short_flag('i')
                .long_flag("input")
                .about("ELF/PRX file input path")
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("output")
                .short_flag('o')
                .long_flag("output")
                .about("BIN/SPRX file output path")
                .arg_required_else_help(true),
        )
}

fn main() {
    let path = std::path::PathBuf::from("gta-5.prx");
    let file_data = std::fs::read(path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

    // Get the ELF file's build-id
    let abi_shdr: SectionHeader = file
        .section_header_by_name(".sce_module_param")
        .expect("section table should be parseable")
        .expect("file should have a .sce_module_param section");

    // Find lazy-parsing types for the common ELF sections (we want .dynsym, .dynstr, .hash)
    /*let common = file.find_common_data().expect("shdrs should parse");
    let (dynsyms, strtab) = (common.dynsyms.unwrap(), common.dynsyms_strs.unwrap());
    let hash_table = common.sysv_hash.unwrap();

    // Use the hash table to find a given symbol in it.
    let name = b"memset";
    let (sym_idx, sym) = hash_table
        .find(name, &dynsyms, &strtab)
        .expect("hash table and symbols should parse")
        .unwrap();

    // Verify that we got the same symbol from the hash table we expected
    assert_eq!(sym_idx, 2);
    assert_eq!(strtab.get(sym.st_name as usize).unwrap(), "memset");
    assert_eq!(sym, dynsyms.get(sym_idx).unwrap());*/

    /*let matches = cli().get_matches();
    match matches.subcommand() {
        Some(("input", sub_matches)) => {
            println!(
                "input file is {}",
                sub_matches.get_one::<String>("INPUT").expect("required")
            );
        }
        Some(("output", sub_matches)) => {
            println!(
                "output file is {}",
                sub_matches.get_one::<String>("OUTPUT").expect("required")
            );
        }
        _ => unreachable!(), // If all subcommands are defined above, anything else is unreachable!()
    }*/

    /*let paid = args.paid;
    if !(0..=0xFFFFFFFFFFFFFFFF).contains(&paid) {
        eprintln!("invalid program authentication id: 0x{:016X}", paid);
        std::process::exit(2);
    }

    let ptype = opt.ptype.unwrap_or(SignedElfExInfo::PTYPE_FAKE);

    // Check if the ptype is a valid string
    let ptype = match ptype.to_lowercase().as_str() {
        "fake" => SignedElfExInfo::PTYPE_FAKE,
        "npdrm_exec" => SignedElfExInfo::PTYPE_NPDRM_EXEC,
        "npdrm_dynlib" => SignedElfExInfo::PTYPE_NPDRM_DYNLIB,
        "system_exec" => SignedElfExInfo::PTYPE_SYSTEM_EXEC,
        "system_dynlib" => SignedElfExInfo::PTYPE_SYSTEM_DYNLIB,
        "host_kernel" => SignedElfExInfo::PTYPE_HOST_KERNEL,
        "secure_module" => SignedElfExInfo::PTYPE_SECURE_MODULE,
        "secure_kernel" => SignedElfExInfo::PTYPE_SECURE_KERNEL,
        _ => match u64::from_str(&ptype) {
            Ok(parsed_ptype) => parsed_ptype,
            Err(_) => {
                eprintln!("invalid program type: 0x{:016X}", ptype);
                std::process::exit(2);
            }
        },
    };

    if !(0..=0xFFFFFFFFFFFFFFFF).contains(&ptype) {
        eprintln!("invalid program type: 0x{:016X}", ptype);
        std::process::exit(2);
    }

    let app_version = opt.app_version;
    if !(0..=0xFFFFFFFFFFFFFFFF).contains(&app_version) {
        eprintln!("invalid application version: 0x{:016X}", app_version);
        std::process::exit(2);
    }

    let fw_version = opt.fw_version;
    if !(0..=0xFFFFFFFFFFFFFFFF).contains(&fw_version) {
        eprintln!("invalid firmware version: 0x{:016X}", fw_version);
        std::process::exit(2);
    }

    let auth_info = opt.auth_info.unwrap_or_else(Vec::new);

    let elf_file_path = opt.input;
    println!("loading elf file: {:?}", elf_file_path);
    let elf_file = ElfFile::new();
    if let Ok(mut f) = File::open(&elf_file_path) {
        if let Err(err) = elf_file.load(&mut f) {
            eprintln!(
                "unable to load elf file: {} ({})",
                elf_file_path.to_str().unwrap(),
                err
            );
            std::process::exit(2);
        }
    }

    let fself_file_path = opt.output;
    println!("saving fake signed elf file: {:?}", fself_file_path);
    if let Ok(mut f) = File::create(&fself_file_path) {
        let self_file =
            SignedElfFile::new(&elf_file, paid, ptype, app_version, fw_version, auth_info);
        if let Err(err) = self_file.save(&mut f) {
            eprintln!(
                "unable to save fself file: {} ({})",
                fself_file_path.to_str().unwrap(),
                err
            );
            std::process::exit(2);
        }
    }

    println!("done");*/
}
