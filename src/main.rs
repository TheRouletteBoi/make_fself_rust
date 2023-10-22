use anyhow::{Context, Result};
use clap::Parser;
use elf::{endian::AnyEndian, section::SectionHeader, ElfBytes};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::process::exit;
use std::str::FromStr;

fn write_file(filename: &str, buffer: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(filename)
        .unwrap_or_else(|e| {
            println!("{}", e);
            exit(1);
        });

    file.write_all(buffer).unwrap();
}

fn parse_cli() -> String {
    let Some(in_file) = std::env::args().skip(1).next() else {
        println!("Missing Filename!");
        exit(1);
    };
    in_file
}

// $ cargo run gta-5.prx gta-5.sprx
fn main() -> Result<()> {
    let filename = parse_cli();
    let contents: Vec<u8> = std::fs::read(&filename).unwrap_or_else(|e| {
        println!("{}", e);
        std::process::exit(1);
    });

    let file = ElfBytes::<AnyEndian>::minimal_parse(&contents[..]).unwrap_or_else(|e| {
        println!("{}", e);
        exit(1);
    });

    let thing: SectionHeader = file
        .section_header_by_name(".sce_module_param")
        .expect("section table should be parsable")
        .expect("file should have a .sce_module_param section");

    println!("{:#?}", thing);

    println!("{:#?}", file.ehdr);

    let new_header: Vec<u8> = vec![0; 100];
    write_file(
        &filename.replace(".prx", ".sprx"),
        &new_header
            .into_iter()
            .chain(contents.into_iter())
            .collect::<Vec<u8>>(),
    );

    Ok(())
}
