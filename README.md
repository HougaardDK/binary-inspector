# Binary Inspector

A small Rust CLI for looking inside Windows PE and Linux ELF files. It prints the
file size, headers, sections and imports. For PE files, imports are grouped by DLL.
For ELF files, it lists the shared libraries and imported symbols.

## Build and run

From the repo folder on Linux, with Rust 1.65 or newer:

```bash
cargo build --release --locked
./target/release/binary-inspector /bin/ls
```

For a PE file, give it the path to your file:

```bash
./target/release/binary-inspector ./sample.dll
```
