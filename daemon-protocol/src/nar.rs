//! Copying a NAR that has no length of its own.
//!
//! `Op::NarFromPath`'s reply is the raw NAR wire format written directly onto
//! the connection (`lix/libstore/daemon.cc:796`, `to << dumpPath(...)`) — no
//! byte-count prefix, no framing. The only way to know where it ends is to
//! walk its structure exactly the way `lix/libutil/archive.cc`'s parser does
//! (`ParseSink::parse`/`parseRoot`) and stop once the grammar says so, since
//! the connection carries more protocol traffic right after.
//!
//! This does the same walk, but is not a decoder: every field it reads is
//! copied to `sink` byte-for-byte (including its own length prefix and
//! padding) rather than reinterpreted, since nothing here needs the NAR's
//! *meaning* — [`crate::connection::DaemonConnection::nar_from_path`]'s only
//! job is handing the caller the exact same bytes `nix store dump-path` would
//! have produced, for hashing/compression, not for extraction.
//!
//! Grammar (from `archive.cc`'s `parse`/`parseRoot`), all strings wire-encoded:
//!
//! ```text
//! archive  := "nix-archive-1" node
//! node     := "(" "type" ( regular | directory | symlink ) ")"
//! regular  := "regular" ["executable" ""] "contents" <u64 size> <size bytes + padding>
//! directory:= "directory" entry* ")"        -- note: consumes its own trailing ")"
//! entry    := "entry" "(" "name" <name> "node" node ")"
//! symlink  := "symlink" "target" <target>
//! ```

use crate::wire::{WireRead, WireWrite};

const MAGIC: &str = "nix-archive-1";

#[derive(Debug, thiserror::Error)]
pub enum NarError {
    #[error("i/o error copying a NAR: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed NAR: expected {expected:?}, got {got:?}")]
    Unexpected { expected: &'static str, got: String },
    #[error("malformed NAR: unknown node type {0:?}")]
    UnknownType(String),
}

/// Copy one NAR — magic plus a single root node — from `reader` to `sink`,
/// byte for byte, stopping exactly where the archive ends.
pub async fn copy_nar<R, W>(reader: &mut R, sink: &mut W) -> Result<(), NarError>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    let magic = copy_str(reader, sink).await?;
    expect(&magic, MAGIC)?;
    copy_node(reader, sink).await
}

async fn copy_u64<R, W>(reader: &mut R, sink: &mut W) -> Result<u64, NarError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let value = reader.read_wire_u64().await?;
    sink.write_wire_u64(value).await?;
    Ok(value)
}

/// Read a length-prefixed, padded string, mirroring the exact wire bytes
/// (prefix, payload, padding) to `sink`, and returning the decoded value so
/// the caller can make a grammar decision on it.
async fn copy_str<R, W>(reader: &mut R, sink: &mut W) -> Result<String, NarError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let bytes = reader.read_wire_bytes().await?;
    sink.write_wire_bytes(&bytes).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn expect(got: &str, expected: &'static str) -> Result<(), NarError> {
    if got == expected {
        Ok(())
    } else {
        Err(NarError::Unexpected {
            expected,
            got: got.to_string(),
        })
    }
}

// Recursive, so it has to be boxed: `async fn` cannot recurse into itself
// directly. `directory` is the only case that does — a node inside a
// directory entry is itself a full node.
fn copy_node<'a, R, W>(
    reader: &'a mut R,
    sink: &'a mut W,
) -> futures_util::future::BoxFuture<'a, Result<(), NarError>>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    Box::pin(async move {
        expect(&copy_str(reader, sink).await?, "(")?;
        expect(&copy_str(reader, sink).await?, "type")?;
        let node_type = copy_str(reader, sink).await?;

        match node_type.as_str() {
            "regular" => {
                let mut tag = copy_str(reader, sink).await?;
                if tag == "executable" {
                    expect(&copy_str(reader, sink).await?, "")?;
                    tag = copy_str(reader, sink).await?;
                }
                expect(&tag, "contents")?;
                let size = copy_u64(reader, sink).await?;
                copy_padded(reader, sink, size).await?;
                expect(&copy_str(reader, sink).await?, ")")?;
            }
            "symlink" => {
                expect(&copy_str(reader, sink).await?, "target")?;
                copy_str(reader, sink).await?; // the target itself, unused
                expect(&copy_str(reader, sink).await?, ")")?;
            }
            "directory" => loop {
                let tag = copy_str(reader, sink).await?;
                if tag == ")" {
                    // Directories consume their own closing paren — there is
                    // no separate one to expect after this loop, unlike
                    // `regular`/`symlink` above.
                    break;
                }
                expect(&tag, "entry")?;
                expect(&copy_str(reader, sink).await?, "(")?;
                expect(&copy_str(reader, sink).await?, "name")?;
                copy_str(reader, sink).await?; // the entry's name, unused
                expect(&copy_str(reader, sink).await?, "node")?;
                copy_node(reader, sink).await?;
                expect(&copy_str(reader, sink).await?, ")")?;
            },
            other => return Err(NarError::UnknownType(other.to_string())),
        }

        Ok(())
    })
}

/// Mirror `len` raw content bytes plus their padding to a multiple of eight —
/// unlike every other field here, file contents are not themselves
/// length-prefixed again (the `u64 size` just read *is* their length), so
/// this only pads, it does not re-prefix.
async fn copy_padded<R, W>(reader: &mut R, sink: &mut W, len: u64) -> Result<(), NarError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut remaining = len;
    let mut buf = [0u8; 65536];
    while remaining > 0 {
        let chunk = remaining.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..chunk]).await?;
        sink.write_all(&buf[..chunk]).await?;
        remaining -= chunk as u64;
    }

    let padding = kubernix_types::wire::padding(len as usize);
    if padding > 0 {
        let zeroes = [0u8; 8];
        reader.read_exact(&mut [0u8; 8][..padding]).await?;
        sink.write_all(&zeroes[..padding]).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal, well-formed NAR for a single regular file — enough to
    /// exercise magic + `regular` without needing a real Nix store anywhere
    /// near the test.
    fn nar_regular_file(contents: &[u8], executable: bool) -> Vec<u8> {
        let mut w = Vec::new();
        kubernix_types::wire::write_bytes(&mut w, MAGIC.as_bytes());
        kubernix_types::wire::write_bytes(&mut w, b"(");
        kubernix_types::wire::write_bytes(&mut w, b"type");
        kubernix_types::wire::write_bytes(&mut w, b"regular");
        if executable {
            kubernix_types::wire::write_bytes(&mut w, b"executable");
            kubernix_types::wire::write_bytes(&mut w, b"");
        }
        kubernix_types::wire::write_bytes(&mut w, b"contents");
        kubernix_types::wire::write_u64(&mut w, contents.len() as u64);
        w.extend_from_slice(contents);
        w.extend(std::iter::repeat_n(
            0u8,
            kubernix_types::wire::padding(contents.len()),
        ));
        kubernix_types::wire::write_bytes(&mut w, b")");
        w
    }

    fn nar_directory(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut w = Vec::new();
        kubernix_types::wire::write_bytes(&mut w, MAGIC.as_bytes());
        kubernix_types::wire::write_bytes(&mut w, b"(");
        kubernix_types::wire::write_bytes(&mut w, b"type");
        kubernix_types::wire::write_bytes(&mut w, b"directory");
        for (name, node) in entries {
            kubernix_types::wire::write_bytes(&mut w, b"entry");
            kubernix_types::wire::write_bytes(&mut w, b"(");
            kubernix_types::wire::write_bytes(&mut w, b"name");
            kubernix_types::wire::write_bytes(&mut w, name.as_bytes());
            kubernix_types::wire::write_bytes(&mut w, b"node");
            // `node` here already has its own leading magic-less structure
            // starting at `(` — strip the outer magic this helper would
            // otherwise duplicate.
            w.extend_from_slice(node);
            kubernix_types::wire::write_bytes(&mut w, b")");
        }
        kubernix_types::wire::write_bytes(&mut w, b")");
        w
    }

    #[tokio::test]
    async fn copies_a_regular_file_byte_for_byte() {
        let nar = nar_regular_file(b"hello kubernix", false);
        let mut reader = std::io::Cursor::new(nar.clone());
        let mut sink = Vec::new();
        copy_nar(&mut reader, &mut sink).await.unwrap();
        assert_eq!(sink, nar);
    }

    #[tokio::test]
    async fn copies_an_executable_file_byte_for_byte() {
        let nar = nar_regular_file(b"#!/bin/sh\necho hi\n", true);
        let mut reader = std::io::Cursor::new(nar.clone());
        let mut sink = Vec::new();
        copy_nar(&mut reader, &mut sink).await.unwrap();
        assert_eq!(sink, nar);
    }

    #[tokio::test]
    async fn copies_an_empty_directory_byte_for_byte() {
        let nar = nar_directory(&[]);
        let mut reader = std::io::Cursor::new(nar.clone());
        let mut sink = Vec::new();
        copy_nar(&mut reader, &mut sink).await.unwrap();
        assert_eq!(sink, nar);
    }

    #[tokio::test]
    async fn copies_a_directory_with_a_nested_file_byte_for_byte() {
        let file = nar_regular_file(b"contents", false);
        let entry_node = strip_magic(&file);
        let nar = nar_directory(&[("a.txt", entry_node)]);

        let mut reader = std::io::Cursor::new(nar.clone());
        let mut sink = Vec::new();
        copy_nar(&mut reader, &mut sink).await.unwrap();
        assert_eq!(sink, nar);
    }

    /// Strips the leading magic a `nar_regular_file`/`nar_directory` helper
    /// wrote, leaving just the `(` ... node bytes — for embedding one NAR's
    /// node as a directory entry's `node` in another.
    fn strip_magic(nar: &[u8]) -> Vec<u8> {
        // The magic is `write_wire_bytes(MAGIC)`: an 8-byte length prefix plus the
        // bytes themselves plus padding to a multiple of eight.
        let prefix_len = 8 + MAGIC.len() + kubernix_types::wire::padding(MAGIC.len());
        nar[prefix_len..].to_vec()
    }

    #[tokio::test]
    async fn wrong_magic_is_rejected() {
        let mut w = Vec::new();
        kubernix_types::wire::write_bytes(&mut w, b"not-a-nar");
        let mut reader = std::io::Cursor::new(w);
        let mut sink = Vec::new();
        assert!(copy_nar(&mut reader, &mut sink).await.is_err());
    }

    #[tokio::test]
    async fn truncated_input_is_an_error_not_a_panic() {
        let nar = nar_regular_file(b"hello kubernix, a longer body", false);
        // Cut it well before the declared content length ends.
        let truncated = &nar[..nar.len() - 20];
        let mut reader = std::io::Cursor::new(truncated.to_vec());
        let mut sink = Vec::new();
        assert!(copy_nar(&mut reader, &mut sink).await.is_err());
    }
}
