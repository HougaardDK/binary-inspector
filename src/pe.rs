use std::io::{Result, Write};

use crate::bytes::{bad, label, name, slice, tail, Reader, Region};

struct Section {
    name: String,
    raw: Region,
    virtual_size: u32,
    flags: u32,
}

fn reader(data: &[u8]) -> Reader<'_> {
    Reader { data, little: true }
}

fn machine(id: u16) -> &'static str {
    match id {
        0x14c => "x86",
        0x8664 => "x86-64",
        0x1c0 | 0x1c2 | 0x1c4 => "ARM",
        0xaa64 => "ARM64",
        0xa641 => "ARM64EC",
        0xa64e => "ARM64X",
        0x200 => "IA-64",
        0x5032 => "RISC-V 32",
        0x5064 => "RISC-V 64",
        _ => "unknown",
    }
}

pub fn inspect(data: &[u8], out: &mut impl Write) -> Result<()> {
    let pe = u64::from(reader(data).u32(0x3c)?);
    let header = tail(data, pe)?;
    if !header.starts_with(b"PE\0\0") {
        return Err(bad("missing PE signature"));
    }
    let coff = reader(slice(header, 4, 20)?);
    let id = coff.u16(0)?;
    let count = coff.u16(2)?;
    let opt_size = u64::from(coff.u16(16)?);
    let opt = reader(slice(header, 24, opt_size)?);
    let magic = opt.u16(0)?;
    let wide = magic == 0x20b;
    if !wide && magic != 0x10b {
        return Err(bad("unknown PE optional header"));
    }
    let dir_off = if wide { 112 } else { 96 };
    let image_base = opt.word(if wide { 24 } else { 28 }, wide)?;
    let header_size = u64::from(opt.u32(60)?);
    // count ends right where the dirs start
    let n = u64::from(opt.u32(dir_off - 4)?);
    let dirs = slice(&opt.data[dir_off..], 0, n * 8)?;

    let mut sections = Vec::new();
    let table = slice(header, 24 + opt_size, u64::from(count) * 40)?;
    for data in table.chunks_exact(40) {
        let r = reader(data);
        let end = data[..8].iter().position(|&byte| byte == 0).unwrap_or(8);
        sections.push(Section {
            name: label(&data[..end]),
            raw: Region {
                addr: r.u32(12)?.into(),
                offset: r.u32(20)?.into(),
                size: r.u32(16)?.into(),
            },
            virtual_size: r.u32(8)?,
            flags: r.u32(36)?,
        });
    }

    let flags = coff.u16(18)?;
    let kind = if flags & 0x2000 != 0 { "DLL" } else { "image" };
    let format = if wide { "PE32+" } else { "PE32" };
    writeln!(out, "Format: {format} ({kind})\n\nPE headers")?;
    writeln!(out, "  Header offset: {pe:#x}")?;
    writeln!(out, "  Machine: {} ({id:#06x})", machine(id))?;
    writeln!(out, "  Timestamp: {}", coff.u32(4)?)?;
    writeln!(out, "  Characteristics: {flags:#06x}")?;
    writeln!(out, "  DLL characteristics: {:#06x}", opt.u16(70)?)?;
    // todo: show subsystem names
    writeln!(out, "  Subsystem: {}", opt.u16(68)?)?;
    writeln!(out, "  Entry RVA: {:#x}", opt.u32(16)?)?;
    writeln!(out, "  Image base: {image_base:#x}")?;
    writeln!(out, "  Image size: {:#x}", opt.u32(56)?)?;
    writeln!(out, "  File alignment: {:#x}", opt.u32(36)?)?;
    writeln!(out, "  Section alignment: {:#x}", opt.u32(32)?)?;

    writeln!(out, "\nSections ({count})")?;
    if !sections.is_empty() {
        writeln!(
            out,
            "  {:<9} {:>10} {:>10} {:>10} {:>10} {:>10}",
            "Name", "RVA", "Virtual", "Offset", "Raw size", "Flags"
        )?;
    }
    for s in &sections {
        writeln!(
            out,
            "  {:<9} {:>#10x} {:>#10x} {:>#10x} {:>#10x} {:#010x}",
            s.name, s.raw.addr, s.virtual_size, s.raw.offset, s.raw.size, s.flags
        )?;
    }

    let headers = Region {
        addr: 0,
        offset: 0,
        size: header_size,
    };
    let at = |addr| {
        if let Some(bytes) = headers.at(data, addr)? {
            return Ok(bytes);
        }
        for s in &sections {
            if let Some(bytes) = s.raw.at(data, addr)? {
                return Ok(bytes);
            }
        }
        Err(bad("no file data at the PE RVA"))
    };

    writeln!(out, "\nImports")?;
    let width = if wide { 8 } else { 4 };
    let ordinal_bit = 1 << (width * 8 - 1);
    let mut found = false;
    'dirs: for (index, delayed) in [(1, false), (13, true)] {
        let dir = match dirs.chunks_exact(8).nth(index) {
            Some(dir) => reader(dir),
            None => continue,
        };
        let rva = u64::from(dir.u32(0)?);
        if rva == 0 {
            continue;
        }
        let bytes = at(rva)?;
        let len = u64::from(dir.u32(4)?);
        let bytes = if len == 0 {
            bytes
        } else {
            slice(bytes, 0, len)?
        };
        let size = if delayed { 32 } else { 20 };
        for desc in bytes.chunks_exact(size) {
            if desc.iter().all(|&b| b == 0) {
                continue 'dirs;
            }
            let r = reader(desc);
            let base = if delayed && r.u32(0)? & 1 == 0 {
                image_base
            } else {
                0
            };
            let get = |addr: u64| {
                if addr < base {
                    return Err(bad("delay import address is below the image base"));
                }
                at(addr - base)
            };
            let dll = u64::from(r.u32(if delayed { 4 } else { 12 })?);
            if dll == 0 {
                return Err(bad("PE import has no DLL name"));
            }
            let dll = name(get(dll)?, 0)?;
            let tag = if delayed { " (delay load)" } else { "" };
            writeln!(out, "  {dll}{tag}")?;
            found = true;

            let mut thunk = r.u32(if delayed { 16 } else { 0 })?;
            if thunk == 0 {
                if !delayed && r.u32(4)? != 0 {
                    writeln!(out, "    (bound addresses only)")?;
                    continue;
                }
                thunk = r.u32(if delayed { 12 } else { 16 })?;
            }
            if thunk == 0 {
                continue;
            }

            let mut list = get(thunk.into())?.chunks_exact(width);
            loop {
                let entry = list
                    .next()
                    .ok_or_else(|| bad("unterminated PE lookup table"))?;
                let value = reader(entry).word(0, wide)?;
                if value == 0 {
                    break;
                }
                if value & ordinal_bit != 0 {
                    writeln!(out, "    #{}", value & 0xffff)?;
                } else {
                    writeln!(out, "    {}", name(get(value)?, 2)?)?;
                }
            }
        }
        return Err(bad("bad PE imports"));
    }
    if !found {
        writeln!(out, "  (none)")?;
    }
    Ok(())
}
