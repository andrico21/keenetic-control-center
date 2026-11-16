//! The last line of an audit file, read from its end without reading the rest.

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

use super::{AuditEntry, AuditError, GENESIS_HASH, chain, json_error};
use crate::persist::io_error;

/// Bytes read per step while searching backwards for a newline.
const BLOCK: usize = 4096;

/// The sequence number and hash the next entry chains to.
///
/// They come from the last entry of the active file or, when it holds none, of the newest
/// archive that holds one; genesis without either. Only that entry is read and only its
/// own hash is checked: its link to its predecessor and every earlier entry are left to
/// full verification.
///
/// # Errors
///
/// Returns an I/O error, or a JSON or chain error for a last line that is complete but
/// not a valid entry.
pub(super) fn chain_head(
    dir: &Path,
    active: &mut File,
    active_path: &Path,
) -> Result<(u64, String), AuditError> {
    let mut last = last_entry(active, active_path)?;
    if last.is_none() {
        for path in chain::rotated_files(dir)?.iter().rev() {
            let mut archive = File::open(path).map_err(|error| io_error(path, error))?;
            last = last_entry(&mut archive, path)?;
            if last.is_some() {
                break;
            }
        }
    }
    Ok(last.map_or_else(
        || (1, GENESIS_HASH.to_owned()),
        |entry| (entry.seq.saturating_add(1), entry.hash),
    ))
}

/// The last entry of `file`, with its own hash checked.
///
/// # Errors
///
/// As [`chain_head`].
pub(super) fn last_entry(file: &mut File, path: &Path) -> Result<Option<AuditEntry>, AuditError> {
    let len = file
        .metadata()
        .map_err(|error| io_error(path, error))?
        .len();
    let Some(line) = last_line(file, len).map_err(|error| io_error(path, error))? else {
        return Ok(None);
    };
    let entry: AuditEntry = serde_json::from_slice(&line).map_err(|error| json_error(&error))?;
    if chain::calculate_hash(&entry)? != entry.hash {
        return Err(AuditError::Chain { seq: entry.seq });
    }
    Ok(Some(entry))
}

/// Where the unterminated end of a `len`-byte file starts, or `None` when the file is
/// empty or ends in `\n`.
///
/// # Errors
///
/// Returns the I/O error of a seek or read.
pub(super) fn torn_start<R>(reader: &mut R, len: u64) -> io::Result<Option<u64>>
where
    R: Read + Seek,
{
    if len == 0 || ends_in_newline(reader, len)? {
        return Ok(None);
    }
    line_start(reader, len).map(Some)
}

/// The bytes `start..end` of `reader`.
///
/// # Errors
///
/// Returns the I/O error of a seek or read.
pub(super) fn read_range<R>(reader: &mut R, start: u64, end: u64) -> io::Result<Vec<u8>>
where
    R: Read + Seek,
{
    let _: u64 = reader.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    let _: usize = reader
        .take(end.saturating_sub(start))
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The last non-empty line of a `len`-byte file without its `\n`; a final line without
/// one counts as a line.
///
/// # Errors
///
/// Returns the I/O error of a seek or read.
fn last_line<R>(reader: &mut R, len: u64) -> io::Result<Option<Vec<u8>>>
where
    R: Read + Seek,
{
    let mut end = len;
    while end > 0 {
        let line_end = if ends_in_newline(reader, end)? {
            end.saturating_sub(1)
        } else {
            end
        };
        let start = line_start(reader, line_end)?;
        if start < line_end {
            return read_range(reader, start, line_end).map(Some);
        }
        end = start;
    }
    Ok(None)
}

/// Whether byte `end - 1` is `\n`.
///
/// # Errors
///
/// Returns the I/O error of a seek or read.
fn ends_in_newline<R>(reader: &mut R, end: u64) -> io::Result<bool>
where
    R: Read + Seek,
{
    let mut last = [0_u8; 1];
    let _: u64 = reader.seek(SeekFrom::Start(end.saturating_sub(1)))?;
    reader.read_exact(&mut last)?;
    Ok(last == *b"\n")
}

/// The offset just after the last `\n` before `end`, or 0 when there is none.
///
/// # Errors
///
/// Returns the I/O error of a seek or read.
fn line_start<R>(reader: &mut R, end: u64) -> io::Result<u64>
where
    R: Read + Seek,
{
    let mut block = vec![0_u8; BLOCK];
    let step = u64::try_from(BLOCK).unwrap_or(u64::MAX);
    let mut until = end;
    while until > 0 {
        let from = until.saturating_sub(step);
        let size = usize::try_from(until.saturating_sub(from)).unwrap_or(BLOCK);
        let chunk = block.get_mut(..size).unwrap_or_default();
        let _: u64 = reader.seek(SeekFrom::Start(from))?;
        reader.read_exact(chunk)?;
        if let Some(newline) = chunk.iter().rposition(|byte| *byte == b'\n') {
            let after = u64::try_from(newline).unwrap_or(u64::MAX).saturating_add(1);
            return Ok(from.saturating_add(after));
        }
        until = from;
    }
    Ok(0)
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]
mod tests {
    use core::error::Error;
    use std::io::{self, Cursor, Read, Seek, SeekFrom};

    use super::{BLOCK, last_line, torn_start};

    /// A reader that counts the bytes it hands out.
    struct Counting {
        /// The counted reader.
        inner: Cursor<Vec<u8>>,
        /// Bytes read so far.
        read: usize,
    }

    impl Read for Counting {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let read = self.inner.read(buf)?;
            self.read = self.read.saturating_add(read);
            Ok(read)
        }
    }

    impl Seek for Counting {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    fn log(lines: u32, last: &str) -> Counting {
        let mut bytes = Vec::new();
        for index in 0..lines {
            bytes.extend_from_slice(
                format!("{{\"seq\":{index},\"pad\":\"{}\"}}\n", "x".repeat(90)).as_bytes(),
            );
        }
        bytes.extend_from_slice(last.as_bytes());
        Counting {
            inner: Cursor::new(bytes),
            read: 0,
        }
    }

    /// `B-01` / `SEC2-05`: the chain head of a 2 MB log is found by reading about one
    /// block from its end, not the log.
    #[test]
    fn the_tail_read_is_bounded_by_the_last_line() -> Result<(), Box<dyn Error>> {
        let mut file = log(20_000, "{\"seq\":20000}\n");
        let len = file.inner.get_ref().len();

        let line = last_line(&mut file, u64::try_from(len)?)?;

        assert_eq!(line.as_deref(), Some(b"{\"seq\":20000}".as_slice()));
        assert!(len > 2_000_000, "{len}");
        assert!(
            file.read <= BLOCK.saturating_mul(2),
            "read {} bytes",
            file.read
        );
        Ok(())
    }

    /// `B-03` / `SEC2-04`: only bytes after the last `\n` are torn; a file ending in `\n`
    /// costs one byte to check.
    #[test]
    fn the_torn_tail_starts_after_the_last_newline() -> Result<(), Box<dyn Error>> {
        let mut whole = log(1_000, "");
        let whole_len = u64::try_from(whole.inner.get_ref().len())?;
        assert_eq!(torn_start(&mut whole, whole_len)?, None);
        assert_eq!(whole.read, 1);
        let mut torn = log(1_000, "{\"seq\":1000,\"pa");
        let torn_len = u64::try_from(torn.inner.get_ref().len())?;
        assert_eq!(torn_start(&mut torn, torn_len)?, Some(whole_len));
        assert_eq!(torn_start(&mut log(0, "{\"se"), 4)?, Some(0));
        assert_eq!(torn_start(&mut log(0, ""), 0)?, None);
        Ok(())
    }
}
