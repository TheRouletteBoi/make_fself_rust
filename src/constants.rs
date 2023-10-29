pub mod signed_elf_file {
    pub static HAS_NPDRM: u32 = 1;
    pub static COMMON_HEADER_FMT: &[u8; 5] = b"<4s4B";
    pub static COMMON_HEADER_FMT_SIZE: i128 = 8;
    pub static EXT_HEADER_FMT: &[u8; 9] = b"<I2HQ2H4x";
    pub static EXT_HEADER_FMT_SIZE: i128 = 24;
    pub static MAGIC: &[u8; 4] = b"\x4F\x15\x3D\x1D";
    pub static VERSION: i8 = 0x00;
    pub static MODE: i8 = 0x01;
    pub static ENDIAN: i8 = 0x01;
    pub static ATTRIBS: i8 = 0x12;
    pub static KEY_TYPE: u32 = 0x101;
    pub static FLAGS_SEGMENT_SIGNED_SHIFT: i32 = 4;
    pub static FLAGS_SEGMENT_SIGNED_MASK: i32 = 0x7;
}

pub mod signed_elf_entry {
    pub static FMT: &[u8; 3] = b"<4Q";
    pub static FMT_SIZE: i128 = 32;

    pub static PROPS_ORDER_SHIFT: i128 = 0;
    pub static PROPS_ORDER_MASK: i128 = 0x1;
    pub static PROPS_ENCRYPTED_SHIFT: i128 = 1;
    pub static PROPS_ENCRYPTED_MASK: i128 = 0x1;
    pub static PROPS_SIGNED_SHIFT: i128 = 2;
    pub static PROPS_SIGNED_MASK: i128 = 0x1;
    pub static PROPS_COMPRESSED_SHIFT: i128 = 3;
    pub static PROPS_COMPRESSED_MASK: i128 = 0x1;
    pub static PROPS_WINDOW_BITS_SHIFT: i128 = 8;
    pub static PROPS_WINDOW_BITS_MASK: i128 = 0x7;
    pub static PROPS_HAS_BLOCKS_SHIFT: i128 = 11;
    pub static PROPS_HAS_BLOCKS_MASK: i128 = 0x1;
    pub static PROPS_BLOCK_SIZE_SHIFT: i128 = 12;
    pub static PROPS_BLOCK_SIZE_MASK: i128 = 0xF;
    pub static PROPS_HAS_DIGESTS_SHIFT: i128 = 16;
    pub static PROPS_HAS_DIGESTS_MASK: i128 = 0x1;
    pub static PROPS_HAS_EXTENTS_SHIFT: i128 = 17;
    pub static PROPS_HAS_EXTENTS_MASK: i128 = 0x1;
    pub static PROPS_HAS_META_SEGMENT_SHIFT: i128 = 20;
    pub static PROPS_HAS_META_SEGMENT_MASK: i128 = 0x1;
    pub static PROPS_SEGMENT_INDEX_SHIFT: i128 = 20;
    pub static PROPS_SEGMENT_INDEX_MASK: i128 = 0xFFFF;
    pub static PROPS_DEFAULT_BLOCK_SIZE: i128 = 0x1000;
    pub static PROPS_META_SEGMENT_MASK: i128 = 0xF0000;
}

pub mod signed_elf_ex_info {
    pub static FMT: &[u8; 6] = b"<4Q32s";
    pub static FMT_SIZE: i128 = 64;
}

pub mod signed_elf_npdrm_control_block {
    pub static FMT: &[u8; 11] = b"<H14x19s13s";
    pub static FMT_SIZE: i128 = 48;
}

pub mod signed_elf_meta_block {
    pub static FMT: &[u8; 4] = b"<80x";
    pub static FMT_SIZE: i128 = 80;
}

pub mod signed_elf_meta_footer {
    pub static FMT: &[u8; 8] = b"<48xI28x";
    pub static FMT_SIZE: i128 = 80;
}
