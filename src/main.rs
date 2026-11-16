mod bytes;
mod elf;
mod pe;

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "Usage: binary-inspector <file>";

fn inspect(path: &Path, out: &mut impl Write) -> io::Result<()> {
    if !fs::metadata(path)?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a regular file",
        ));
    }
    let data = fs::read(path)?;
    let elf = data.starts_with(b"\x7fELF");
    if !elf && !data.starts_with(b"MZ") {
        return Err(bytes::bad("expected an ELF or PE file"));
    }

    writeln!(out, "File: {path:?}")?;
    writeln!(out, "Size: {} bytes", data.len())?;
    if elf {
        elf::inspect(&data, out)?;
    } else {
        pe::inspect(&data, out)?;
    }
    out.flush()
}

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let arg = match (args.next(), args.next()) {
        (Some(arg), None) => arg,
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    if arg == "-h" || arg == "--help" {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let path = Path::new(&arg);
    let mut out = io::BufWriter::new(io::stdout().lock());
    match inspect(path, &mut out) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{path:?}: {err}");
            ExitCode::FAILURE
        }
    }
}
