use crypto::digest::Digest;
use crypto::sha1::Sha1;
use goblin::elf::reloc::*;
use goblin::elf::section_header::*;
use goblin::Object;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

fn handle_elf(elf: goblin::elf::Elf, buff: &[u8], hasher: &mut Box<dyn Digest>) -> String {
    let relevant_sections = vec![".text", ".data", ".bss", ".rodata"];
    elf.section_headers.iter().for_each(|hdr| {
        let name = elf.shdr_strtab.get(hdr.sh_name).unwrap().unwrap();
        if relevant_sections.contains(&name) {
            match hdr.sh_type {
                SHT_PROGBITS => {
                    hasher.input_str(&name);
                    hasher.input(&buff[hdr.file_range()]);
                }
                SHT_NOBITS => {
                    hasher.input_str(&format!("BSS: {}", hdr.sh_size));
                }
                _ => panic!("Unknown section type"),
            }
        }
    });
    let mut syms = elf.syms.to_vec();
    elf.shdr_relocs.iter().for_each(|(_, sec)| {
        //println!("Reloc for section {}", elf.shdr_strtab.get(elf.section_headers[*idx].sh_name).unwrap().unwrap());
        let mut relocs = sec.to_vec();
        relocs.sort_by_key(|r| r.r_offset);
        relocs.iter().for_each(|r| {
            let name = elf.strtab.get(syms[r.r_sym].st_name).unwrap().unwrap();
            let reloc_type = r_to_str(r.r_type, 8);
            assert_eq!(r.r_addend, None);
            hasher.input_str(&format!("{} at {}->{}", reloc_type, r.r_offset, name));
        });
    });
    syms.sort_by_key(|sym| elf.strtab.get(sym.st_name).unwrap().unwrap());
    syms.iter().for_each(|sym| {
        let name = elf.strtab.get(sym.st_name).unwrap().unwrap();
        if !sym.is_import() {
            hasher.input_str(&format!(
                "{}: off {} size {}",
                name, sym.st_value, sym.st_size
            ));
        }
    });
    hasher.result_str()
}

struct RawDigest {
    entries: Vec<String>,
}
impl RawDigest {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl Digest for RawDigest {
    fn input(&mut self, input: &[u8]) {
        self.entries.push(
            input
                .chunks(4)
                .map(|i| format!("{:02X}{:02X}{:02X}{:02X}", i[0], i[1], i[2], i[3]))
                .collect::<Vec<String>>()
                .chunks(8)
                .map(|m| m.join(" "))
                .collect::<Vec<String>>()
                .join("\n"),
        )
    }
    fn result(&mut self, _: &mut [u8]) {
        panic!("Not implemented")
    }
    fn reset(&mut self) {
        self.entries.clear()
    }
    fn output_bits(&self) -> usize {
        panic!("Not implemented")
    }
    fn block_size(&self) -> usize {
        panic!("Not implemented")
    }

    fn output_bytes(&self) -> usize {
        panic!("Not implemented")
    }
    fn input_str(&mut self, input: &str) {
        self.entries.push(String::from(input));
    }
    fn result_str(&mut self) -> String {
        self.entries.join("\n")
    }
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let path = Path::new(&args[1]);
    let mut fd = File::open(path)?;
    let mut buffer = Vec::new();
    fd.read_to_end(&mut buffer)?;
    let dump_raw = args.len() > 2;
    let mut hasher: Box<dyn Digest> = match dump_raw {
        false => Box::new(Sha1::new()),
        true => Box::new(RawDigest::new()),
    };

    if let Ok(Object::Archive(archive)) = Object::parse(&buffer) {
        let mut members = archive.members();
        members.sort();
        members
            .iter()
            .map(|member| {
                hasher.reset();
                let buff = archive.extract(member, &buffer).unwrap();
                match Object::parse(buff) {
                    Ok(Object::Elf(elf)) => Some(format!(
                        "{}\n{}",
                        member,
                        handle_elf(elf, &buff, &mut hasher)
                    )),
                    _ => None,
                }
            })
            .flatten()
            .for_each(|info| println!("{}", info));
    } else {
        println!("Expected archive file.");
    }

    Ok(())
}
