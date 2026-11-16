use std::io::{self, Result};

pub fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

pub fn tail(data: &[u8], offset: u64) -> Result<&[u8]> {
    let offset = usize::try_from(offset).map_err(|_| bad("file offset too large"))?;
    data.get(offset..).ok_or_else(|| bad("offset is past EOF"))
}

pub fn slice(data: &[u8], offset: u64, size: u64) -> Result<&[u8]> {
    let rest = tail(data, offset)?;
    if size > rest.len() as u64 {
        return Err(bad("range runs past EOF"));
    }
    Ok(&rest[..size as usize])
}

pub fn label(data: &[u8]) -> String {
    let mut text = String::new();
    for &byte in data {
        text.extend(std::ascii::escape_default(byte).map(char::from));
    }
    text
}

pub fn name(data: &[u8], offset: u64) -> Result<String> {
    let data = tail(data, offset)?;
    let end = data
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| bad("unterminated name"))?;
    Ok(label(&data[..end]))
}

pub struct Region {
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
}

impl Region {
    pub fn at<'a>(&self, data: &'a [u8], addr: u64) -> Result<Option<&'a [u8]>> {
        if addr < self.addr || addr - self.addr >= self.size {
            return Ok(None);
        }
        let region = slice(data, self.offset, self.size)?;
        Ok(Some(&region[(addr - self.addr) as usize..]))
    }
}

pub struct Reader<'a> {
    pub data: &'a [u8],
    pub little: bool,
}

impl Reader<'_> {
    fn field(&self, off: usize, size: usize) -> Result<&[u8]> {
        // only fixed offsets inside a header or row
        self.data
            .get(off..off + size)
            .ok_or_else(|| bad("short header or table"))
    }

    pub fn u16(&self, off: usize) -> Result<u16> {
        let b = self.field(off, 2)?;
        let n = u16::from_le_bytes([b[0], b[1]]);
        Ok(if self.little { n } else { n.swap_bytes() })
    }

    pub fn u32(&self, off: usize) -> Result<u32> {
        let bytes = self.field(off, 4)?.try_into().unwrap();
        Ok(if self.little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    }

    pub fn word(&self, off: usize, wide: bool) -> Result<u64> {
        if !wide {
            return Ok(self.u32(off)?.into());
        }
        let bytes = self.field(off, 8)?.try_into().unwrap();
        Ok(if self.little {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        })
    }
}
