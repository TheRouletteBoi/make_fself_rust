use anyhow::{Context, Result};
use byteorder::{LittleEndian, WriteBytesExt};
use clap::Parser;
use elf::{endian::AnyEndian, ElfBytes};
use hmac::digest::{KeyInit, OutputSizeUser};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;
use std::{cmp::max, fmt::format};

static BLOCK_SIZE: i128 = 0x4000;
static SIGNATURE_SIZE: i128 = 0x100;
static DIGEST_SIZE: usize = 0x20;
static EMPTY_DIGEST: u8 = b'\x00';
static MAGIC: &[u8; 4] = b"\x7FELF";
static MACHINE_CLASS: u8 = 0x2;
static DATA2LSB: u8 = 0x1;
static SELF_CONTROL_BLOCK_TYPE_NPDRM: u16 = 0x3;
static SELF_NPDRM_CONTROL_BLOCK_CONTENT_ID_SIZE: usize = 0x13;
static SELF_NPDRM_CONTROL_BLOCK_RANDOM_PAD_SIZE: usize = 0xD;

mod constants;
use crate::constants::{signed_elf_meta_footer, signed_elf_npdrm_control_block};
use constants::{signed_elf_entry, signed_elf_ex_info, signed_elf_file, signed_elf_meta_block};

#[derive(Parser)]
struct Cli {
    input_file: std::path::PathBuf,
    output_file: std::path::PathBuf,
    paid: Option<String>,
    program_type: Option<String>,
    app_version: Option<String>,
    fw_version: Option<String>,
    auth_info: Option<String>,
}

enum ProgramSegmentType {
    PtLoad = 0x1,
    PtDynamic = 0x2,
    PtInterp = 0x3,
    PtTls = 0x7,
    PtGnuEhFrame = 0x6474E550,
    PtGnuStack = 0x6474E551,
    PtSceRela = 0x60000000,
    PtSceDynlibdata = 0x61000000,
    PtSceProcparam = 0x61000001,
    PtSceModuleParam = 0x61000002,
    PtSceRelro = 0x61000010,
    PtSceComment = 0x6FFFFF00,
    PtSceVersion = 0x6FFFFF01,
}

#[derive(Debug, Clone, Copy)]
enum ProgramType {
    Fake = 0x1,
    NpdrmExec = 0x4,
    NpdrmDynlib = 0x5,
    SystemExec = 0x8,
    SystemDynlib = 0x9, // including Mono binaries
    HostKernel = 0xC,
    SecureModule = 0xE,
    SecureKernel = 0xF,
}

#[derive(Debug)]
struct SignedElfEntry {
    index: usize,
    props: i128,
    offset: i128,
    filesz: i128,
    memsz: i128,
    data: Box<[u8]>,
    encrypted: bool,
    signed: bool,
    has_digests: bool,
    has_blocks: bool,
    block_size: i128,
    segment_index: usize,
}

impl SignedElfEntry {
    fn new(index: usize) -> SignedElfEntry {
        SignedElfEntry {
            index,
            props: 0,
            offset: 0,
            filesz: 0,
            memsz: 0,
            data: Box::new([]),
            encrypted: false,
            signed: false,
            has_digests: false,
            has_blocks: false,
            block_size: 0,
            segment_index: 0,
        }
    }

    fn encrypted(&mut self, value: bool) {
        self.encrypted = value;

        self.props &=
            !(signed_elf_entry::PROPS_ENCRYPTED_MASK << signed_elf_entry::PROPS_ENCRYPTED_SHIFT);

        if value {
            self.props |=
                signed_elf_entry::PROPS_ENCRYPTED_MASK << signed_elf_entry::PROPS_ENCRYPTED_SHIFT;
        }
    }

    fn signed(&mut self, value: bool) {
        self.signed = value;

        self.props &=
            !(signed_elf_entry::PROPS_SIGNED_MASK << signed_elf_entry::PROPS_SIGNED_SHIFT);

        if value {
            self.props |=
                signed_elf_entry::PROPS_SIGNED_MASK << signed_elf_entry::PROPS_SIGNED_SHIFT;
        }
    }

    fn has_digest(&mut self, value: bool) {
        self.has_digests = value;

        self.props &= !(signed_elf_entry::PROPS_HAS_DIGESTS_MASK
            << signed_elf_entry::PROPS_HAS_DIGESTS_SHIFT);

        if value {
            self.props |= signed_elf_entry::PROPS_HAS_DIGESTS_MASK
                << signed_elf_entry::PROPS_HAS_DIGESTS_SHIFT;
        }
    }

    fn segment_index(&mut self, value: usize) {
        self.segment_index = value;

        self.props &= !(signed_elf_entry::PROPS_SEGMENT_INDEX_MASK
            << signed_elf_entry::PROPS_SEGMENT_INDEX_SHIFT);

        self.props |= (value as i128 & signed_elf_entry::PROPS_SEGMENT_INDEX_MASK)
            << signed_elf_entry::PROPS_SEGMENT_INDEX_SHIFT;
    }

    fn has_blocks(&mut self, value: bool) {
        self.has_blocks = value;

        self.props &=
            !(signed_elf_entry::PROPS_HAS_BLOCKS_MASK << signed_elf_entry::PROPS_HAS_BLOCKS_SHIFT);

        if value {
            self.props |=
                signed_elf_entry::PROPS_HAS_BLOCKS_MASK << signed_elf_entry::PROPS_HAS_BLOCKS_SHIFT;
        }
    }

    fn block_size(&mut self, value: i128) {
        self.block_size = value;

        self.props &=
            !(signed_elf_entry::PROPS_BLOCK_SIZE_MASK << signed_elf_entry::PROPS_BLOCK_SIZE_SHIFT);

        let new_value = if self.has_blocks {
            format!("{:b}", value).len() as i128 - 13 as i128
        } else {
            0
        };

        self.props |= (new_value & signed_elf_entry::PROPS_BLOCK_SIZE_MASK)
            << signed_elf_entry::PROPS_BLOCK_SIZE_SHIFT;
    }
}

#[derive(Debug)]
struct SignedElfExInfo {
    paid: i128,
    ptype: ProgramType,
    app_version: i128,
    fw_version: i128,
    digest: [u8; 32],
}

fn align_up(x: i128, alignment: i128) -> i128 {
    return (x + (alignment - 1)) & !(alignment - 1);
}

fn sign_elf_file(
    elf_file: ElfBytes<AnyEndian>,
    mut output_file: File,
    paid: i128,
    ptype: ProgramType,
    app_version: i128,
    fw_version: i128,
    digest: [u8; 32],
    auth_info: String,
) -> Result<()> {
    let mut flags = 0x02;
    let signed_block_count = 2;

    flags = flags
        | (signed_block_count & signed_elf_file::FLAGS_SEGMENT_SIGNED_MASK)
            << signed_elf_file::FLAGS_SEGMENT_SIGNED_SHIFT;

    let mut version_data: &[u8] = &[];
    let mut entries: Vec<SignedElfEntry> = Vec::new();

    let segments = elf_file.segments().clone().unwrap();

    let mut entry_idx: usize = 0;

    for (index, phdr) in segments.iter().enumerate() {
        if phdr.p_type == ProgramSegmentType::PtSceVersion as u32 {
            version_data = elf_file.segment_data(&phdr).unwrap();
        }

        if ![
            ProgramSegmentType::PtLoad as u32,
            ProgramSegmentType::PtSceRelro as u32,
            ProgramSegmentType::PtSceDynlibdata as u32,
            ProgramSegmentType::PtSceComment as u32,
        ]
        .contains(&phdr.p_type)
        {
            continue;
        }

        let mut meta_entry = SignedElfEntry::new(entry_idx);

        meta_entry.encrypted(false);
        meta_entry.signed(true);
        meta_entry.has_digest(true);
        meta_entry.segment_index(entry_idx + 1);
        entries.push(meta_entry);

        let mut data_entry = SignedElfEntry::new(entry_idx + 1);

        data_entry.encrypted(false);
        data_entry.signed(true);
        data_entry.has_blocks(true);
        data_entry.block_size(BLOCK_SIZE);
        data_entry.segment_index(index);

        entries.push(data_entry);

        entry_idx += 2;
    }

    let num_entries = entries.len();

    let ex_info = SignedElfExInfo {
        paid,
        ptype,
        app_version,
        fw_version,
        digest,
    };

    let mut header_size = signed_elf_file::COMMON_HEADER_FMT_SIZE
        + signed_elf_file::EXT_HEADER_FMT_SIZE
        + num_entries as i128 * signed_elf_entry::FMT_SIZE as i128
        + max(
            elf_file.ehdr.e_ehsize as i128,
            elf_file.ehdr.e_phoff as i128
                + elf_file.ehdr.e_phentsize as i128 * elf_file.ehdr.e_phnum as i128,
        );

    header_size = align_up(header_size, 16);
    header_size += signed_elf_ex_info::FMT_SIZE;

    if signed_elf_file::HAS_NPDRM > 0 {
        header_size += signed_elf_npdrm_control_block::FMT_SIZE;
    }

    let meta_size = num_entries as i128 * signed_elf_meta_block::FMT_SIZE
        + signed_elf_meta_footer::FMT_SIZE
        + SIGNATURE_SIZE;

    entry_idx = 0;
    let mut offset = header_size as i128 + meta_size;
    for (index, phdr) in segments.iter().enumerate() {
        if ![
            ProgramSegmentType::PtLoad as u32,
            ProgramSegmentType::PtSceRelro as u32,
            ProgramSegmentType::PtSceDynlibdata as u32,
            ProgramSegmentType::PtSceComment as u32,
        ]
        .contains(&phdr.p_type)
        {
            continue;
        }

        println!("processing segment #{:02}...", index);

        let num_blocks = align_up(phdr.p_filesz as i128, BLOCK_SIZE) / BLOCK_SIZE;
        {
            let meta_entry: &mut SignedElfEntry = entries.get_mut(entry_idx).unwrap();
            meta_entry.data =
                vec![EMPTY_DIGEST; DIGEST_SIZE * num_blocks as usize].into_boxed_slice();
            meta_entry.offset = offset;
            meta_entry.memsz = meta_entry.data.len() as i128;
            meta_entry.filesz = meta_entry.data.len() as i128;

            offset += meta_entry.filesz;
            offset = align_up(offset, 16);
        }
        {
            let data_entry: &mut SignedElfEntry = entries.get_mut(entry_idx + 1).unwrap();
            data_entry.data = Box::from(elf_file.segment_data(&phdr).unwrap());
            data_entry.offset = offset;
            data_entry.memsz = phdr.p_filesz as i128;
            data_entry.filesz = phdr.p_filesz as i128;

            offset += data_entry.filesz;
            offset = align_up(offset, 16);
        }

        entry_idx += 2;
    }

    let mut common_header_pack = vec![];

    // COMMON_HEADER_FMT: '<4s4B'
    // -  4s : A string of length 4 bytes.
    common_header_pack.write(signed_elf_file::MAGIC).unwrap();
    // -  4b : Four signed bytes.
    common_header_pack
        .write_i8(signed_elf_file::VERSION)
        .unwrap();
    common_header_pack.write_i8(signed_elf_file::MODE).unwrap();
    common_header_pack
        .write_i8(signed_elf_file::ENDIAN)
        .unwrap();
    common_header_pack
        .write_i8(signed_elf_file::ATTRIBS)
        .unwrap();

    output_file.write(&common_header_pack)?;

    let mut extended_header_pack = vec![];

    // EXT_HEADER_FMT: '<I2HQ2H4x'
    // -  I : Unsigned int (4 bytes)
    extended_header_pack
        .write_u32::<LittleEndian>(signed_elf_file::KEY_TYPE)
        .unwrap();
    // -  2H : Two unsigned shorts (each 2 bytes)
    extended_header_pack
        .write_u16::<LittleEndian>(header_size as u16)
        .unwrap();
    // -  Q : Unsigned long long (8 bytes)
    extended_header_pack
        .write_u16::<LittleEndian>(meta_size as u16)
        .unwrap();
    // -  2H : Two unsigned shorts (each 2 bytes)
    extended_header_pack
        .write_u32::<LittleEndian>(offset as u32)
        .unwrap();
    // // -  4x : Four pad bytes
    extended_header_pack.write_u32::<LittleEndian>(0).unwrap();
    extended_header_pack
        .write_u16::<LittleEndian>(num_entries as u16)
        .unwrap();
    extended_header_pack
        .write_u16::<LittleEndian>(flags as u16)
        .unwrap();
    extended_header_pack.write_u32::<LittleEndian>(0).unwrap();

    output_file.write(&extended_header_pack)?;

    for entry in entries.iter() {
        let mut entry_pack = vec![];

        // FMT: '<4Q'
        entry_pack
            .write_u64::<LittleEndian>(entry.props as u64)
            .unwrap();
        entry_pack
            .write_u64::<LittleEndian>(entry.offset as u64)
            .unwrap();
        entry_pack
            .write_u64::<LittleEndian>(entry.filesz as u64)
            .unwrap();
        entry_pack
            .write_u64::<LittleEndian>(entry.memsz as u64)
            .unwrap();

        output_file.write(&entry_pack)?;
    }

    // ELF SAVE
    let mut ehdr_pack = vec![];

    // FMT = '<4s5B6xB'
    // -  4s : A string of length 4 bytes.
    ehdr_pack.write(MAGIC).unwrap();
    // -  5B : Five unsigned bytes.
    ehdr_pack.write_u8(MACHINE_CLASS).unwrap();
    ehdr_pack.write_u8(DATA2LSB).unwrap();
    ehdr_pack.write_u8(elf_file.ehdr.version as u8).unwrap();
    ehdr_pack.write_u8(elf_file.ehdr.osabi as u8).unwrap();
    ehdr_pack.write_u8(elf_file.ehdr.abiversion as u8).unwrap();
    // -  6x : Six pad bytes.
    ehdr_pack.write_u48::<LittleEndian>(0).unwrap();
    // -  B  : Unsigned byte
    ehdr_pack.write_u8(0).unwrap();

    // EX_FMT : '<2HI3QI6H'
    // -  2H : Two unsigned shorts (each 2 bytes)
    ehdr_pack
        .write_u16::<LittleEndian>(elf_file.ehdr.e_type)
        .unwrap();
    // -  I : Unsigned int (4 bytes)
    ehdr_pack
        .write_u16::<LittleEndian>(elf_file.ehdr.e_machine)
        .unwrap();
    ehdr_pack
        .write_u32::<LittleEndian>(elf_file.ehdr.version as u32)
        .unwrap();
    // -  3Q : Three unsigned long long (each 8 bytes)
    ehdr_pack
        .write_u64::<LittleEndian>(elf_file.ehdr.e_entry as u64)
        .unwrap();
    ehdr_pack
        .write_u64::<LittleEndian>(elf_file.ehdr.e_phoff as u64)
        .unwrap();
    ehdr_pack
        .write_u64::<LittleEndian>(elf_file.ehdr.e_shoff as u64)
        .unwrap();
    // -  I : Unsigned int (4 bytes)
    ehdr_pack
        .write_u32::<LittleEndian>(elf_file.ehdr.e_flags as u32)
        .unwrap();
    // -  6H : Six unsigned shorts (each 2 bytes)
    ehdr_pack
        .write_u16::<LittleEndian>(elf_file.ehdr.e_ehsize as u16)
        .unwrap();
    ehdr_pack
        .write_u16::<LittleEndian>(elf_file.ehdr.e_phentsize as u16)
        .unwrap();
    ehdr_pack
        .write_u16::<LittleEndian>(elf_file.ehdr.e_phnum as u16)
        .unwrap();
    ehdr_pack
        .write_u16::<LittleEndian>(elf_file.ehdr.e_shentsize as u16)
        .unwrap();
    // Because of ignore_shdrs = True
    ehdr_pack.write_u16::<LittleEndian>(0 as u16).unwrap();
    ehdr_pack
        .write_u16::<LittleEndian>(elf_file.ehdr.e_shstrndx as u16)
        .unwrap();

    output_file.write(&ehdr_pack)?;

    if elf_file.ehdr.e_phentsize > 0 && elf_file.ehdr.e_phnum > 0 {
        for phdr in segments.iter() {
            let mut phdr_pack = vec![];

            // FMT = '<2I6Q'
            // -  2I : Two signed integers (each 4 bytes)
            phdr_pack
                .write_u32::<LittleEndian>(phdr.p_type as u32)
                .unwrap();
            phdr_pack
                .write_u32::<LittleEndian>(phdr.p_flags as u32)
                .unwrap();
            // -  6Q : Six unsigned long long integers (each 8 bytes)
            phdr_pack
                .write_u64::<LittleEndian>(phdr.p_offset as u64)
                .unwrap();
            phdr_pack
                .write_u64::<LittleEndian>(phdr.p_vaddr as u64)
                .unwrap();
            phdr_pack
                .write_u64::<LittleEndian>(phdr.p_paddr as u64)
                .unwrap();
            phdr_pack
                .write_u64::<LittleEndian>(phdr.p_filesz as u64)
                .unwrap();
            phdr_pack
                .write_u64::<LittleEndian>(phdr.p_memsz as u64)
                .unwrap();
            phdr_pack
                .write_u64::<LittleEndian>(phdr.p_align as u64)
                .unwrap();

            output_file.write(&phdr_pack)?;
        }
    }

    // ELF EXT INFO
    let mut elf_ext_info_pack = vec![];

    // FMT = '<4Q32s'
    // - 4Q : 4 unsigned long long
    elf_ext_info_pack
        .write_u64::<LittleEndian>(paid as u64)
        .unwrap();
    elf_ext_info_pack
        .write_u64::<LittleEndian>(ex_info.ptype as u64)
        .unwrap();
    elf_ext_info_pack
        .write_u64::<LittleEndian>(ex_info.app_version as u64)
        .unwrap();
    elf_ext_info_pack
        .write_u64::<LittleEndian>(ex_info.fw_version as u64)
        .unwrap();
    // - 32S : 32 char[]
    elf_ext_info_pack.write(&ex_info.digest).unwrap();

    output_file.write(&elf_ext_info_pack)?;

    if signed_elf_file::HAS_NPDRM > 0 {
        let mut npdrm_control_block_pack = vec![];

        // FMT = '<H14x19s13s'
        // -  H : Unsigned short (2 bytes)
        npdrm_control_block_pack
            .write_u16::<LittleEndian>(SELF_CONTROL_BLOCK_TYPE_NPDRM as u16)
            .unwrap();

        // -  14x : 14 pad bytes
        npdrm_control_block_pack
            .write_u16::<LittleEndian>(0)
            .unwrap();
        npdrm_control_block_pack
            .write_u16::<LittleEndian>(0)
            .unwrap();
        npdrm_control_block_pack
            .write_u16::<LittleEndian>(0)
            .unwrap();
        npdrm_control_block_pack
            .write_u16::<LittleEndian>(0)
            .unwrap();
        npdrm_control_block_pack
            .write_u16::<LittleEndian>(0)
            .unwrap();
        npdrm_control_block_pack
            .write_u16::<LittleEndian>(0)
            .unwrap();
        npdrm_control_block_pack
            .write_u16::<LittleEndian>(0)
            .unwrap();
        // -  19s : A string of length 19 bytes
        npdrm_control_block_pack
            .write(&vec![b'\0'; SELF_NPDRM_CONTROL_BLOCK_CONTENT_ID_SIZE])
            .unwrap();
        npdrm_control_block_pack
            .write(&vec![b'\0'; SELF_NPDRM_CONTROL_BLOCK_RANDOM_PAD_SIZE])
            .unwrap();
        // -  13s : A string of length 13 bytes

        output_file.write(&npdrm_control_block_pack)?;
    }

    // Meta Block
    for _ in 0..num_entries {
        let mut meta_block_pack = vec![];

        // FMT = '<80x'
        meta_block_pack.write_u128::<LittleEndian>(0).unwrap();
        meta_block_pack.write_u128::<LittleEndian>(0).unwrap();
        meta_block_pack.write_u128::<LittleEndian>(0).unwrap();
        meta_block_pack.write_u128::<LittleEndian>(0).unwrap();
        meta_block_pack.write_u128::<LittleEndian>(0).unwrap();

        output_file.write(&meta_block_pack)?;
    }

    // Meta Footer

    let mut meta_footer_pack = vec![];
    // FMT = '<48xI28x'
    meta_footer_pack.write_u128::<LittleEndian>(0).unwrap();
    meta_footer_pack.write_u128::<LittleEndian>(0).unwrap();
    meta_footer_pack.write_u128::<LittleEndian>(0).unwrap();
    meta_footer_pack
        .write_u32::<LittleEndian>(0x10000 as u32)
        .unwrap();
    meta_footer_pack.write_u128::<LittleEndian>(0).unwrap();
    meta_footer_pack.write_u48::<LittleEndian>(0).unwrap();
    meta_footer_pack.write_u48::<LittleEndian>(0).unwrap();

    output_file.write(&meta_footer_pack)?;

    if auth_info.is_empty() {
        output_file
            .write(&vec![b'\0'; SIGNATURE_SIZE as usize])
            .unwrap();
    }

    let mut start_offset = 0;
    for entry in entries.iter() {
        let mut entry_body_pack = vec![];

        entry_body_pack.write_all(&entry.data).unwrap();

        if start_offset == 0 {
            start_offset = entry.offset as usize + entry.data.len();
        } else {
            while start_offset < entry.offset as usize {
                entry_body_pack.write_u8(0).unwrap();
                start_offset += 1;
            }

            start_offset = entry.offset as usize + entry.data.len();
        }

        output_file.write(&entry_body_pack).unwrap();
    }

    if !version_data.is_empty() {
        output_file.write_all(version_data)?;
    }

    Ok(())
}

// $ cargo run gta-5.prx gta-5.sprx
fn main() -> Result<()> {
    let args = Cli::parse();

    let paid: i128 = args
        .paid
        .unwrap_or_default()
        .parse::<i128>()
        .unwrap_or(0x3100000000000002);

    let program_type: ProgramType = match args
        .program_type
        .unwrap_or("0".to_string())
        .parse::<i64>()
        .unwrap_or_default()
    {
        0x1 => ProgramType::Fake,
        0x4 => ProgramType::NpdrmExec,
        0x5 => ProgramType::NpdrmDynlib,
        0x8 => ProgramType::SystemExec,
        0x9 => ProgramType::SystemDynlib,
        0xC => ProgramType::HostKernel,
        0xE => ProgramType::SecureModule,
        0xF => ProgramType::SecureKernel,
        _ => ProgramType::Fake,
    };

    let app_verision: i128 = args
        .app_version
        .unwrap_or("0".to_string())
        .parse::<i128>()
        .unwrap_or_default();

    let fw_version: i128 = args
        .fw_version
        .unwrap_or("0".to_string())
        .parse::<i128>()
        .unwrap_or_default();

    let auth_info: String = args.auth_info.unwrap_or_default();

    let input_file_data = std::fs::read(&args.input_file)
        .with_context(|| format!("could not read file `{:?}`", args.input_file))
        .unwrap();

    let file_bytes = input_file_data.as_slice();
    let elf_file: ElfBytes<AnyEndian> = ElfBytes::<AnyEndian>::minimal_parse(file_bytes).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(file_bytes);
    let digest: [u8; 32] = hasher.finalize().into();

    let output_file = File::create(&args.output_file)?;

    sign_elf_file(
        elf_file,
        output_file,
        paid,
        program_type,
        app_verision,
        fw_version,
        digest,
        auth_info,
    )
}
