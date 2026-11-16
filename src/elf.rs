use std::io::{Result, Write};
use std::slice::ChunksExact;

use crate::bytes::{bad, name, slice, tail, Reader, Region};

const SYMTAB: u32 = 2;
const STRTAB: u32 = 3;
const DYNAMIC: u32 = 6;
const DYNSYM: u32 = 11;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NEEDED: u64 = 1;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_STRSZ: u64 = 10;
const DT_SYMENT: u64 = 11;
const DT_GNU_HASH: u64 = 0x6ffffef5;

struct Section {
    name: u32,
    kind: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

fn section(r: Reader<'_>, wide: bool) -> Result<Section> {
    let word = |off32, off64| r.word(if wide { off64 } else { off32 }, wide);
    Ok(Section {
        name: r.u32(0)?,
        kind: r.u32(4)?,
        flags: word(8, 8)?,
        addr: word(12, 16)?,
        offset: word(16, 24)?,
        size: word(20, 32)?,
        link: r.u32(if wide { 40 } else { 24 })?,
        entsize: word(36, 56)?,
    })
}

fn machine(id: u16) -> &'static str {
    match id {
        3 => "x86",
        8 => "MIPS",
        20 => "PowerPC",
        21 => "PowerPC64",
        22 => "S390",
        40 => "ARM",
        62 => "x86-64",
        183 => "AArch64",
        243 => "RISC-V",
        258 => "LoongArch",
        _ => "unknown",
    }
}

fn section_type(id: u32) -> String {
    match id {
        0 => "NULL",
        1 => "PROGBITS",
        SYMTAB => "SYMTAB",
        STRTAB => "STRTAB",
        4 => "RELA",
        5 => "HASH",
        DYNAMIC => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        DYNSYM => "DYNSYM",
        14 => "INIT_ARRAY",
        15 => "FINI_ARRAY",
        17 => "GROUP",
        0x6ffffff6 => "GNU_HASH",
        0x6ffffffd => "VERDEF",
        0x6ffffffe => "VERNEED",
        0x6fffffff => "VERSYM",
        _ => return format!("{id:#x}"),
    }
    .into()
}

pub fn inspect(data: &[u8], out: &mut impl Write) -> Result<()> {
    let ident = slice(data, 0, 16)?;
    let wide = match ident[4] {
        1 => false,
        2 => true,
        _ => return Err(bad("bad ELF header")),
    };
    let little = match ident[5] {
        1 => true,
        2 => false,
        _ => return Err(bad("bad ELF header")),
    };
    let read = |data| Reader { data, little };
    let r = read(data);
    if ident[6] != 1 || r.u32(20)? != 1 {
        return Err(bad("unknown ELF version"));
    }

    let bits = if wide { 64 } else { 32 };
    let kind = r.u16(16)?;
    let id = r.u16(18)?;
    let entry = r.word(24, wide)?;
    let ph_off = r.word(if wide { 32 } else { 28 }, wide)?;
    let sh_off = r.word(if wide { 40 } else { 32 }, wide)?;
    let end = if wide { 48 } else { 36 };
    let flags = r.u32(end)?;
    let ph_size = usize::from(r.u16(end + 6)?);
    let mut ph_count = u64::from(r.u16(end + 8)?);
    let sh_size = usize::from(r.u16(end + 10)?);
    let mut sh_count = u64::from(r.u16(end + 12)?);
    let mut names = u32::from(r.u16(end + 14)?);

    // big counts go in section 0
    if sh_off != 0 && (sh_count == 0 || names == 0xffff || ph_count == 0xffff) {
        let first = read(slice(data, sh_off, sh_size as u64)?);
        if sh_count == 0 {
            sh_count = first.word(if wide { 32 } else { 20 }, wide)?;
            if sh_count == 0 {
                return Err(bad("missing extended section count"));
            }
        }
        if names == 0xffff {
            names = first.u32(if wide { 40 } else { 24 })?;
        }
        if ph_count == 0xffff {
            ph_count = first.u32(if wide { 44 } else { 28 })?.into();
        }
    }
    if (sh_off == 0 && (sh_count != 0 || names != 0 || ph_count == 0xffff))
        || (ph_off == 0 && ph_count != 0)
    {
        return Err(bad("missing ELF header table"));
    }

    let mut sections = Vec::new();
    for row in header_rows(data, sh_off, sh_count, sh_size, if wide { 64 } else { 40 })? {
        sections.push(section(read(row), wide)?);
    }
    let names = if names == 0 {
        None
    } else {
        Some(strings(data, &sections, names)?)
    };

    let mut segments = Vec::new();
    for row in header_rows(data, ph_off, ph_count, ph_size, if wide { 56 } else { 32 })? {
        let r = read(row);
        segments.push((
            r.u32(0)?,
            Region {
                addr: r.word(if wide { 16 } else { 8 }, wide)?,
                offset: r.word(if wide { 8 } else { 4 }, wide)?,
                size: r.word(if wide { 32 } else { 16 }, wide)?,
            },
        ));
    }

    let order = if little {
        "little endian"
    } else {
        "big endian"
    };
    let kind_name = match kind {
        1 => "relocatable",
        2 => "executable",
        3 => "shared object or PIE",
        4 => "core dump",
        _ => "unknown",
    };
    writeln!(out, "Format: ELF{bits} ({order})\n\nELF header")?;
    writeln!(out, "  Type: {kind_name} ({kind:#x})")?;
    writeln!(out, "  Machine: {} ({id:#x})", machine(id))?;
    writeln!(out, "  OS ABI: {} (version {})", ident[7], ident[8])?;
    writeln!(out, "  Entry address: {entry:#x}")?;
    writeln!(out, "  Flags: {flags:#x}")?;
    writeln!(out, "  Program headers: {ph_count} at {ph_off:#x}")?;
    writeln!(out, "  Section headers: {sh_count} at {sh_off:#x}")?;

    writeln!(out, "\nSections ({sh_count})")?;
    if !sections.is_empty() {
        writeln!(
            out,
            "  {:>3}  {:<24} {:<12} {:>10} {:>10} {:>10} {:>10}",
            "No.", "Name", "Type", "Address", "Offset", "Size", "Flags"
        )?;
    }
    for (i, s) in sections.iter().enumerate() {
        let title = match (names, s.name) {
            (_, 0) | (None, _) => "-".into(),
            (Some(names), offset) => name(names, offset.into())?,
        };
        writeln!(
            out,
            "  {i:>3}  {title:<24} {:<12} {:>#10x} {:>#10x} {:>#10x} {:>#10x}",
            section_type(s.kind),
            s.addr,
            s.offset,
            s.size,
            s.flags
        )?;
    }

    let at = |addr| {
        for (kind, segment) in &segments {
            if *kind == PT_LOAD {
                if let Some(bytes) = segment.at(data, addr)? {
                    return Ok(bytes);
                }
            }
        }
        Err(bad("ELF address outside load segments"))
    };

    let dyn_section = sections.iter().find(|s| s.kind == DYNAMIC);
    let dynamic = if let Some(s) = dyn_section {
        slice(data, s.offset, s.size)?
    } else if let Some((_, s)) = segments.iter().find(|(kind, _)| *kind == PT_DYNAMIC) {
        slice(data, s.offset, s.size)?
    } else {
        &[]
    };
    let tags = dynamic_tags(read(dynamic), wide)?;
    let tag = |want| {
        tags.iter()
            .find(|&&(key, _)| key == want)
            .map(|&(_, value)| value)
    };
    let strs = || {
        if let Some(s) = dyn_section {
            return strings(data, &sections, s.link);
        }
        let addr = tag(DT_STRTAB).ok_or_else(|| bad("missing dynamic string table"))?;
        let len = tag(DT_STRSZ).ok_or_else(|| bad("missing dynamic string table size"))?;
        slice(at(addr)?, 0, len)
    };

    writeln!(out, "\nLibraries")?;
    if tag(DT_NEEDED).is_some() {
        let table = strs()?;
        for &(_, offset) in tags.iter().filter(|&&(key, _)| key == DT_NEEDED) {
            writeln!(out, "  {}", name(table, offset)?)?;
        }
    } else {
        writeln!(out, "  (none)")?;
    }

    writeln!(out, "\nImports")?;
    let mut found = false;
    let mut has_dynsym = false;
    for s in &sections {
        if s.kind != DYNSYM && !(kind == 1 && s.kind == SYMTAB) {
            continue;
        }
        has_dynsym |= s.kind == DYNSYM;
        found |= print_symbols(
            read(slice(data, s.offset, s.size)?),
            strings(data, &sections, s.link)?,
            wide,
            s.entsize,
            out,
        )?;
    }
    if !has_dynsym {
        if let Some(addr) = tag(DT_SYMTAB) {
            let stride = tag(DT_SYMENT).ok_or_else(|| bad("missing dynamic symbol entry size"))?;
            let count = if let Some(hash) = tag(DT_HASH) {
                u64::from(read(at(hash)?).u32(4)?)
            } else if let Some(hash) = tag(DT_GNU_HASH) {
                gnu_symbol_count(read(at(hash)?), wide)?
            } else {
                return writeln!(out, "  (dynamic symbol count unavailable)");
            };
            let size = count
                .checked_mul(stride)
                .ok_or_else(|| bad("symbol table too large"))?;
            found |= print_symbols(read(slice(at(addr)?, 0, size)?), strs()?, wide, stride, out)?;
        }
    }
    if !found {
        writeln!(out, "  (none)")?;
    }
    Ok(())
}

fn header_rows(
    data: &[u8],
    offset: u64,
    count: u64,
    size: usize,
    min: usize,
) -> Result<ChunksExact<'_, u8>> {
    if count == 0 {
        return Ok([].chunks_exact(min));
    }
    if size < min {
        return Err(bad("ELF header entry is too short"));
    }
    let rest = tail(data, offset)?;
    if count > (rest.len() / size) as u64 {
        return Err(bad("ELF header table runs past EOF"));
    }
    Ok(rest[..count as usize * size].chunks_exact(size))
}

fn strings<'a>(data: &'a [u8], sections: &[Section], index: u32) -> Result<&'a [u8]> {
    let s = sections
        .get(index as usize)
        .filter(|s| s.kind == STRTAB)
        .ok_or_else(|| bad("invalid ELF string table index"))?;
    slice(data, s.offset, s.size)
}

fn dynamic_tags(r: Reader<'_>, wide: bool) -> Result<Vec<(u64, u64)>> {
    let width = if wide { 8 } else { 4 };
    let mut tags = Vec::new();
    for row in r.data.chunks_exact(width * 2) {
        let r = Reader {
            data: row,
            little: r.little,
        };
        let tag = r.word(0, wide)?;
        if tag == 0 {
            return Ok(tags);
        }
        tags.push((tag, r.word(width, wide)?));
    }
    if r.data.is_empty() {
        return Ok(tags);
    }
    Err(bad("unterminated ELF dynamic table"))
}

fn gnu_symbol_count(r: Reader<'_>, wide: bool) -> Result<u64> {
    let buckets = u64::from(r.u32(0)?);
    let first = u64::from(r.u32(4)?);
    let bloom_words = u64::from(r.u32(8)?);
    let buckets_off = 16 + bloom_words * if wide { 8 } else { 4 };
    if buckets == 0 {
        return Ok(first);
    }
    let table = slice(r.data, buckets_off, buckets * 4)?;
    let mut last = 0;
    for bucket in table.chunks_exact(4) {
        let entry = Reader {
            data: bucket,
            little: r.little,
        };
        last = last.max(u64::from(entry.u32(0)?));
    }
    if last == 0 {
        return Ok(first);
    }
    if last < first {
        return Err(bad("bad GNU hash"));
    }
    // biggest bucket value starts the last chain
    let chain_off = buckets_off + (buckets + last - first) * 4;
    let low_byte = if r.little { 0 } else { 3 };
    for (n, chain) in tail(r.data, chain_off)?.chunks_exact(4).enumerate() {
        if chain[low_byte] & 1 != 0 {
            return Ok(last + n as u64 + 1);
        }
    }
    Err(bad("unterminated GNU hash chain"))
}

fn print_symbols(
    r: Reader<'_>,
    table: &[u8],
    wide: bool,
    stride: u64,
    out: &mut impl Write,
) -> Result<bool> {
    let min = if wide { 24 } else { 16 };
    let stride = usize::try_from(stride).map_err(|_| bad("invalid ELF symbol entry size"))?;
    if stride < min || r.data.len() % stride != 0 {
        return Err(bad("invalid ELF symbol table size"));
    }
    let mut found = false;
    // todo: show GNU symbol versions too
    for row in r.data.chunks_exact(stride) {
        let r = Reader {
            data: row,
            little: r.little,
        };
        let index = r.u32(0)?;
        if index != 0 && r.u16(if wide { 6 } else { 14 })? == 0 {
            writeln!(out, "  {}", name(table, index.into())?)?;
            found = true;
        }
    }
    Ok(found)
}
