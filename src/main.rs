use anyhow::{Context, Result};
use clap::Parser;
use elf::{endian::AnyEndian, section::SectionHeader, ElfBytes};
use hmac::{Hmac, Mac};
use object::{Object, ObjectSection};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::format;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::process::exit;
use std::str::FromStr;

#[derive(Parser)]
struct Cli {
    input_file: std::path::PathBuf,
    output_file: std::path::PathBuf,
}

// TODO(Roulette): Rename PType enum
#[derive(Debug, Clone, Copy)]
enum PType {
    Fake = 0x1,
    NpdrmExec = 0x4,
    NpdrmDynlib = 0x5,
    SystemExec = 0x8,
    SystemDynlib = 0x9, // including Mono binaries
    HostKernel = 0xC,
    SecureModule = 0xE,
    SecureKernel = 0xF,
}

struct signed_elf_entry {}

// $ cargo run gta-5.prx gta-5.sprx
fn main() -> Result<()> {
    let args = Cli::parse();

    let input_file_data = std::fs::read(&args.input_file)
        .with_context(|| format!("could not read file `{:?}`", args.input_file))?;

    let input_data_raw = input_file_data.as_slice();

    let elf_bytes = ElfBytes::<AnyEndian>::minimal_parse(input_data_raw)?;

    let obj_file = object::File::parse(input_data_raw)?;

    // TODO(Roulette): move these values to Cli parser
    let paid: i64 = 0x3100000000000002;
    let ptype = PType::Fake;
    let app_version = 0;
    let fw_version = 0;
    let auth_info = 0;

    Ok(())
}
