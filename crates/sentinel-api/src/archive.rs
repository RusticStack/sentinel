//! Whole-artifact archives (`tar` and `zip`) assembled from a manifest while they stream.
//!
//! The archive is a `Read` over the manifest's entries: headers and trailers are generated into one small reused
//! buffer, entry bodies are read straight into the caller's buffer, and nothing is staged on disk. Every entry is
//! hashed as it passes and its last chunk is withheld when the digest or length is wrong, so a damaged entry ends
//! the stream short of the length the response promised instead of completing as a valid archive. Bodies are
//! stored, never compressed, which makes the total length a function of the manifest alone: the response states it
//! up front, and a failure surfaces to the client as a body shorter than its `Content-Length`.

use std::io::{self, Read};

use sentinel_store::objects::Entry;

/// Sizes and offsets at or past this need zip64 fields (the format's 32-bit marker value).
const ZIP64_LIMIT: u64 = 0xFFFF_FFFF;
/// The largest size a ustar header field holds in octal (eleven digits); larger ones use base-256.
const TAR_OCTAL_MAX: u64 = 0o77_777_777_777;
/// The central directory is generated this many bytes at a time.
const CENTRAL_BATCH: usize = 4 << 10;
/// BLAKE3-256 of no bytes: a zero-length entry is never opened, only checked against this.
const EMPTY: [u8; 32] = [
    0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
    0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    Tar,
    Zip,
}

impl Format {
    pub(crate) fn parse(text: &str) -> Option<Format> {
        match text {
            "tar" => Some(Format::Tar),
            "zip" => Some(Format::Zip),
            _ => None,
        }
    }

    pub(crate) fn content_type(self) -> &'static str {
        match self {
            Format::Tar => "application/x-tar",
            Format::Zip => "application/zip",
        }
    }

    pub(crate) fn extension(self) -> &'static str {
        match self {
            Format::Tar => "tar",
            Format::Zip => "zip",
        }
    }
}

/// Opens one entry's bytes: the pinned local file or the external copy. The archive verifies what it returns.
pub(crate) type Open = Box<dyn FnMut(&Entry) -> io::Result<Box<dyn Read + Send>> + Send>;

struct Body {
    reader: Box<dyn Read + Send>,
    left: u64,
}

pub(crate) struct Archive {
    format: Format,
    entries: Vec<Entry>,
    open: Open,
    mtime_ms: i64,
    limit: u64,
    /// The next entry to start.
    next: usize,
    body: Option<Body>,
    /// Bytes generated but not yet handed out: headers, padding, descriptors, the central directory.
    head: Vec<u8>,
    head_pos: usize,
    hasher: blake3::Hasher,
    crc: crc32fast::Hasher,
    /// Bytes of finished entries so far (the central directory's start, once all are done).
    offset: u64,
    /// Zip only: each finished entry's CRC-32, for the central directory.
    crcs: Vec<u32>,
    /// Zip only: the central directory's progress: the next entry, its local-header offset, the bytes written.
    cd_next: usize,
    cd_offset: u64,
    cd_size: u64,
    ended: bool,
}

impl Archive {
    pub(crate) fn new(format: Format, entries: Vec<Entry>, mtime_ms: i64, open: Open) -> Archive {
        Archive::with_limit(format, entries, mtime_ms, open, ZIP64_LIMIT)
    }

    fn with_limit(
        format: Format,
        entries: Vec<Entry>,
        mtime_ms: i64,
        open: Open,
        limit: u64,
    ) -> Archive {
        let crcs = match format {
            Format::Zip => Vec::with_capacity(entries.len()),
            Format::Tar => Vec::new(),
        };
        Archive {
            format,
            entries,
            open,
            mtime_ms,
            limit,
            next: 0,
            body: None,
            head: Vec::with_capacity(8 << 10),
            head_pos: 0,
            hasher: blake3::Hasher::new(),
            crc: crc32fast::Hasher::new(),
            offset: 0,
            crcs,
            cd_next: 0,
            cd_offset: 0,
            cd_size: 0,
            ended: false,
        }
    }

    /// Exactly the number of bytes the archive will produce.
    pub(crate) fn len(&self) -> u64 {
        let body: u64 = self.entries.iter().map(|e| self.entry_len(e)).sum();
        match self.format {
            Format::Tar => body + 1024,
            Format::Zip => {
                let mut offset = 0;
                let mut central = 0;
                for entry in &self.entries {
                    central += self.central_len(entry, offset);
                    offset += self.entry_len(entry);
                }
                body + central + self.end_len(body, central)
            }
        }
    }

    /// Opens the first entry now, so one that is missing is an error before any response byte is sent.
    pub(crate) fn prime(&mut self) -> io::Result<()> {
        if self.next == 0 && self.head.is_empty() && !self.entries.is_empty() {
            self.start_entry()?;
        }
        Ok(())
    }

    fn entry_len(&self, entry: &Entry) -> u64 {
        match self.format {
            Format::Tar => {
                let pax = match tar_name(&entry.path) {
                    TarName::Pax => 512 + pad512(pax_record(&entry.path).len() as u64),
                    _ => 0,
                };
                pax + 512 + pad512(entry.len)
            }
            Format::Zip => {
                let big = entry.len >= self.limit;
                let local = 30 + entry.path.len() as u64 + if big { 20 } else { 0 };
                local + entry.len + if big { 24 } else { 16 }
            }
        }
    }

    fn central_len(&self, entry: &Entry, offset: u64) -> u64 {
        let fields = u64::from(entry.len >= self.limit) * 2 + u64::from(offset >= self.limit);
        46 + entry.path.len() as u64 + if fields == 0 { 0 } else { 4 + 8 * fields }
    }

    fn end_len(&self, central_start: u64, central_size: u64) -> u64 {
        if self.end_is_zip64(central_start, central_size) {
            56 + 20 + 22
        } else {
            22
        }
    }

    fn end_is_zip64(&self, central_start: u64, central_size: u64) -> bool {
        self.entries.len() >= 0xFFFF || central_start >= self.limit || central_size >= self.limit
    }

    fn start_entry(&mut self) -> io::Result<()> {
        let entry = &self.entries[self.next];
        self.head.clear();
        self.head_pos = 0;
        match self.format {
            Format::Tar => tar_headers(&mut self.head, entry, self.mtime_ms),
            Format::Zip => zip_local(&mut self.head, entry, self.mtime_ms, self.limit),
        }
        self.hasher.reset();
        self.crc.reset();
        if entry.len == 0 {
            return self.finish_entry();
        }
        self.body = Some(Body {
            reader: (self.open)(entry)?,
            left: entry.len,
        });
        Ok(())
    }

    /// Checks the finished entry against its manifest digest and queues what closes it: tar padding, or the zip
    /// data descriptor.
    fn finish_entry(&mut self) -> io::Result<()> {
        let entry = &self.entries[self.next];
        let digest = if entry.len == 0 {
            EMPTY
        } else {
            *self.hasher.finalize().as_bytes()
        };
        if &digest != entry.digest.as_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "entry content does not match its digest",
            ));
        }
        self.body = None;
        match self.format {
            Format::Tar => {
                let pad = (pad512(entry.len) - entry.len) as usize;
                self.head.resize(self.head.len() + pad, 0);
            }
            Format::Zip => {
                let crc = self.crc.clone().finalize();
                self.crcs.push(crc);
                put32(&mut self.head, 0x0807_4b50);
                put32(&mut self.head, crc);
                if entry.len >= self.limit {
                    put64(&mut self.head, entry.len);
                    put64(&mut self.head, entry.len);
                } else {
                    put32(&mut self.head, entry.len as u32);
                    put32(&mut self.head, entry.len as u32);
                }
            }
        }
        self.offset += self.entry_len(entry);
        self.next += 1;
        Ok(())
    }

    /// Generates what follows the last entry: the tar trailer, or the next stretch of the zip central directory
    /// and, after its last record, the end records.
    fn tail(&mut self) {
        self.head.clear();
        self.head_pos = 0;
        if self.format == Format::Tar {
            self.head.resize(1024, 0);
            self.ended = true;
            return;
        }
        while self.cd_next < self.entries.len() && self.head.len() < CENTRAL_BATCH {
            let before = self.head.len();
            let entry = &self.entries[self.cd_next];
            zip_central(
                &mut self.head,
                entry,
                self.crcs[self.cd_next],
                self.cd_offset,
                self.mtime_ms,
                self.limit,
            );
            self.cd_size += (self.head.len() - before) as u64;
            self.cd_offset += self.entry_len(entry);
            self.cd_next += 1;
        }
        if self.cd_next == self.entries.len() {
            let zip64 = self.end_is_zip64(self.offset, self.cd_size);
            zip_end(
                &mut self.head,
                self.entries.len() as u64,
                self.offset,
                self.cd_size,
                zip64,
            );
            self.ended = true;
        }
    }
}

impl Read for Archive {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.head_pos < self.head.len() {
                let n = buf.len().min(self.head.len() - self.head_pos);
                buf[..n].copy_from_slice(&self.head[self.head_pos..self.head_pos + n]);
                self.head_pos += n;
                return Ok(n);
            }
            if let Some(body) = self.body.as_mut() {
                let want = buf
                    .len()
                    .min(usize::try_from(body.left).unwrap_or(usize::MAX));
                let got = body.reader.read(&mut buf[..want])?;
                if got == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "entry shorter than its manifest length",
                    ));
                }
                self.hasher.update(&buf[..got]);
                if self.format == Format::Zip {
                    self.crc.update(&buf[..got]);
                }
                body.left -= got as u64;
                if body.left == 0 {
                    // The last chunk is withheld on a mismatch: the stream stops short of the promised length.
                    self.head.clear();
                    self.head_pos = 0;
                    self.finish_entry()?;
                }
                return Ok(got);
            }
            if self.next < self.entries.len() {
                self.start_entry()?;
            } else if self.ended {
                return Ok(0);
            } else {
                self.tail();
            }
        }
    }
}

fn pad512(len: u64) -> u64 {
    len.div_ceil(512) * 512
}

fn put16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

enum TarName {
    Plain,
    /// Split at this `/`: what precedes it goes in the header's `prefix` field.
    Prefix(usize),
    Pax,
}

fn tar_name(path: &str) -> TarName {
    let bytes = path.as_bytes();
    if bytes.len() <= 100 {
        return TarName::Plain;
    }
    let from = (bytes.len() - 101).max(1);
    let to = bytes.len().min(156);
    for at in (from..to).rev() {
        if bytes[at] == b'/' {
            return TarName::Prefix(at);
        }
    }
    TarName::Pax
}

/// One pax record, `<length> path=<path>\n`, where the length counts its own digits.
fn pax_record(path: &str) -> Vec<u8> {
    let base = " path=".len() + path.len() + 1;
    let mut length = base + 1;
    while base + length.to_string().len() != length {
        length = base + length.to_string().len();
    }
    format!("{length} path={path}\n").into_bytes()
}

fn octal(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    let mut v = value;
    for slot in field[..digits].iter_mut().rev() {
        *slot = b'0' + (v & 7) as u8;
        v >>= 3;
    }
    field[digits] = 0;
}

fn tar_block(name: &[u8], prefix: &[u8], mode: u32, size: u64, mtime: u64, kind: u8) -> [u8; 512] {
    let mut block = [0u8; 512];
    let name = &name[..name.len().min(100)];
    block[..name.len()].copy_from_slice(name);
    octal(&mut block[100..108], u64::from(mode));
    octal(&mut block[108..116], 0);
    octal(&mut block[116..124], 0);
    if size > TAR_OCTAL_MAX {
        block[124] = 0x80;
        block[128..136].copy_from_slice(&size.to_be_bytes());
    } else {
        octal(&mut block[124..136], size);
    }
    octal(&mut block[136..148], mtime);
    block[148..156].fill(b' ');
    block[156] = kind;
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    block[345..345 + prefix.len()].copy_from_slice(prefix);
    let sum: u32 = block.iter().map(|b| u32::from(*b)).sum();
    for (i, slot) in block[148..154].iter_mut().rev().enumerate() {
        *slot = b'0' + ((sum >> (3 * i)) & 7) as u8;
    }
    block[154] = 0;
    block[155] = b' ';
    block
}

fn tar_headers(out: &mut Vec<u8>, entry: &Entry, mtime_ms: i64) {
    let mtime = u64::try_from(mtime_ms / 1000).unwrap_or(0);
    let path = entry.path.as_bytes();
    let mode = entry.mode & 0o777;
    match tar_name(&entry.path) {
        TarName::Plain => {
            out.extend_from_slice(&tar_block(path, &[], mode, entry.len, mtime, b'0'));
        }
        TarName::Prefix(at) => out.extend_from_slice(&tar_block(
            &path[at + 1..],
            &path[..at],
            mode,
            entry.len,
            mtime,
            b'0',
        )),
        TarName::Pax => {
            let record = pax_record(&entry.path);
            out.extend_from_slice(&tar_block(
                b"pax",
                &[],
                0o644,
                record.len() as u64,
                mtime,
                b'x',
            ));
            out.extend_from_slice(&record);
            out.resize(1024 - 512 + pad512(record.len() as u64) as usize, 0);
            out.extend_from_slice(&tar_block(path, &[], mode, entry.len, mtime, b'0'));
        }
    }
}

/// MS-DOS time and date (two-second resolution, 1980 onwards) of a UTC millisecond timestamp.
fn dos_time(ms: i64) -> (u16, u16) {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    if year < 1980 {
        return (0, (1 << 5) | 1);
    }
    let time = (rem / 3600) << 11 | (rem % 3600 / 60) << 5 | (rem % 60 / 2);
    let date = (year - 1980).min(127) << 9 | month << 5 | day;
    (time as u16, date as u16)
}

fn zip_local(out: &mut Vec<u8>, entry: &Entry, mtime_ms: i64, limit: u64) {
    let big = entry.len >= limit;
    let (time, date) = dos_time(mtime_ms);
    put32(out, 0x0403_4b50);
    put16(out, if big { 45 } else { 20 });
    put16(out, 0x0808);
    put16(out, 0);
    put16(out, time);
    put16(out, date);
    put32(out, 0);
    let size = if big { 0xFFFF_FFFF } else { entry.len as u32 };
    put32(out, size);
    put32(out, size);
    put16(out, entry.path.len() as u16);
    put16(out, if big { 20 } else { 0 });
    out.extend_from_slice(entry.path.as_bytes());
    if big {
        put16(out, 1);
        put16(out, 16);
        put64(out, entry.len);
        put64(out, entry.len);
    }
}

fn zip_central(out: &mut Vec<u8>, entry: &Entry, crc: u32, offset: u64, mtime_ms: i64, limit: u64) {
    let (time, date) = dos_time(mtime_ms);
    let big_size = entry.len >= limit;
    let big_offset = offset >= limit;
    let fields = 2 * u16::from(big_size) + u16::from(big_offset);
    put32(out, 0x0201_4b50);
    put16(out, 3 << 8 | 63);
    put16(out, if fields == 0 { 20 } else { 45 });
    put16(out, 0x0800);
    put16(out, 0);
    put16(out, time);
    put16(out, date);
    put32(out, crc);
    let size = if big_size {
        0xFFFF_FFFF
    } else {
        entry.len as u32
    };
    put32(out, size);
    put32(out, size);
    put16(out, entry.path.len() as u16);
    put16(out, if fields == 0 { 0 } else { 4 + 8 * fields });
    put16(out, 0);
    put16(out, 0);
    put16(out, 0);
    put32(out, (0o100_000 | (entry.mode & 0o777)) << 16);
    put32(
        out,
        if big_offset {
            0xFFFF_FFFF
        } else {
            offset as u32
        },
    );
    out.extend_from_slice(entry.path.as_bytes());
    if fields != 0 {
        put16(out, 1);
        put16(out, 8 * fields);
        if big_size {
            put64(out, entry.len);
            put64(out, entry.len);
        }
        if big_offset {
            put64(out, offset);
        }
    }
}

fn zip_end(out: &mut Vec<u8>, count: u64, start: u64, size: u64, zip64: bool) {
    if zip64 {
        put32(out, 0x0606_4b50);
        put64(out, 44);
        put16(out, 3 << 8 | 63);
        put16(out, 45);
        put32(out, 0);
        put32(out, 0);
        put64(out, count);
        put64(out, count);
        put64(out, size);
        put64(out, start);
        put32(out, 0x0706_4b50);
        put32(out, 0);
        put64(out, start + size);
        put32(out, 1);
    }
    put32(out, 0x0605_4b50);
    put16(out, 0);
    put16(out, 0);
    let count16 = if zip64 { 0xFFFF } else { count as u16 };
    put16(out, count16);
    put16(out, count16);
    put32(out, if zip64 { 0xFFFF_FFFF } else { size as u32 });
    put32(out, if zip64 { 0xFFFF_FFFF } else { start as u32 });
    put16(out, 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_store::objects::Digest;

    fn entry(path: &str, body: &[u8], mode: u32) -> (Entry, Vec<u8>) {
        (
            Entry {
                path: path.to_owned(),
                digest: Digest::from_bytes(*blake3::hash(body).as_bytes()),
                len: body.len() as u64,
                mode,
            },
            body.to_vec(),
        )
    }

    fn assembled(format: Format, items: Vec<(Entry, Vec<u8>)>, limit: u64) -> Vec<u8> {
        let bodies: std::collections::HashMap<String, Vec<u8>> = items
            .iter()
            .map(|(entry, body)| (entry.path.clone(), body.clone()))
            .collect();
        let entries: Vec<Entry> = items.into_iter().map(|(entry, _)| entry).collect();
        let open = Box::new(move |entry: &Entry| {
            let body = bodies[&entry.path].clone();
            Ok(Box::new(io::Cursor::new(body)) as Box<dyn Read + Send>)
        });
        let mut archive = Archive::with_limit(format, entries, 1_700_000_000_000, open, limit);
        let promised = archive.len();
        let mut out = Vec::new();
        archive
            .read_to_end(&mut out)
            .expect("the archive assembles");
        assert_eq!(
            out.len() as u64,
            promised,
            "the stated length is the produced length"
        );
        out
    }

    #[test]
    fn tar_and_zip_produce_the_length_they_state() {
        let items = vec![
            entry("out/report.txt", &b"report"[..], 0o644),
            entry("out/empty", &b""[..], 0o600),
            entry("out/pad", &vec![7u8; 700][..], 0o755),
            entry("deep/a/b/c.json", &vec![1u8; 4096][..], 0o640),
        ];
        assembled(Format::Tar, items.clone(), ZIP64_LIMIT);
        assembled(Format::Zip, items, ZIP64_LIMIT);
    }

    #[test]
    fn a_long_component_gets_a_pax_record_and_a_long_path_a_ustar_prefix() {
        let long = "x".repeat(140);
        let body = b"long"[..].to_vec();
        let items = vec![
            entry(&long, &body, 0o644),
            entry(&format!("{}/tail.txt", "d".repeat(120)), &body, 0o644),
        ];
        let tar = assembled(Format::Tar, items, ZIP64_LIMIT);
        assert_eq!(&tar[156..157], b"x", "the record's own header comes first");
        let record = format!("{} path={long}\n", 3 + 6 + long.len() + 1);
        assert!(
            tar[512..].starts_with(record.as_bytes()),
            "a pax record names the whole path"
        );
        let header = &tar[1024..];
        assert_eq!(&header[..100], &long.as_bytes()[..100]);
        assert_eq!(&header[156..157], b"0");
        let prefixed = &tar[2048..];
        assert_eq!(&prefixed[345..465], "d".repeat(120).as_bytes());
        assert_eq!(&prefixed[..10], b"tail.txt\0\0");
    }

    #[test]
    fn a_size_past_the_thirty_two_bit_marker_uses_zip64_fields() {
        let body = vec![9u8; 200];
        let items = vec![entry("big", &body, 0o644)];
        let zip = assembled(Format::Zip, items, 128);
        assert_eq!(&zip[..4], b"PK\x03\x04");
        assert_eq!(u16::from_le_bytes(zip[4..6].try_into().unwrap()), 45);
        assert_eq!(
            u32::from_le_bytes(zip[18..22].try_into().unwrap()),
            0xFFFF_FFFF
        );
        assert_eq!(u16::from_le_bytes(zip[28..30].try_into().unwrap()), 20);
        assert_eq!(u16::from_le_bytes(zip[33..35].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(zip[35..37].try_into().unwrap()), 16);
        let cd = &zip[30 + 3 + 20 + 200 + 24..];
        assert_eq!(&cd[..4], b"PK\x01\x02");
        assert_eq!(
            u16::from_le_bytes(cd[30..32].try_into().unwrap()),
            4 + 2 * 8
        );
    }

    #[test]
    fn a_damaged_entry_withholds_its_last_chunk_rather_than_completing() {
        let (entry, _) = entry("out/report.txt", &b"report-bytes"[..], 0o644);
        let mut damaged = entry.clone();
        damaged.digest = Digest::from_bytes([0u8; 32]);
        let object = b"report-bytes".to_vec();
        let open = Box::new(move |_: &Entry| {
            Ok(Box::new(io::Cursor::new(object.clone())) as Box<dyn Read + Send>)
        });
        let mut archive = Archive::new(Format::Tar, vec![damaged], 0, open);
        let promised = archive.len();
        let mut out = Vec::new();
        let error = archive.read_to_end(&mut out).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            out.len() < promised as usize,
            "the body stops before its length"
        );
    }

    #[test]
    fn an_empty_manifest_is_a_complete_empty_archive() {
        let tar = assembled(Format::Tar, Vec::new(), ZIP64_LIMIT);
        assert_eq!(tar, vec![0u8; 1024]);
        let zip = assembled(Format::Zip, Vec::new(), ZIP64_LIMIT);
        assert_eq!(&zip[..4], b"PK\x05\x06");
    }
}
