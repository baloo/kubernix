//! Picking the right decoder for a fetched input's actual storage
//! compression.
//!
//! `vm_ops::fetch_input` and `upload::NixStore::fetch_input` both stream a
//! fetched object straight through a decoder into some downstream sink; this
//! is the one place that decoder is chosen, so the two call sites don't each
//! carry their own copy of the match. Kept in `worker` rather than
//! `kubernix_types` -- `Compression` deliberately stays a thin string<->enum
//! boundary type with no decoding dependencies of its own; this dispatch is
//! duplicated (mechanically, a handful of match arms) against the same shape
//! in `server::substitute::fetch_one` rather than forcing that coupling.

use async_compression::tokio::write::{
    BrotliDecoder, BzDecoder, GzipDecoder, Lz4Decoder, XzDecoder, ZstdDecoder,
};
use eyre::bail;
use kubernix_types::Compression;

/// Wrap `sink` in the `AsyncWrite` decoder appropriate for `compression`.
///
/// Not `Send` -- both call sites run inline in the worker's single-job loop
/// (never `tokio::spawn`ed), so there's no reason to force it, and it lets
/// the hash/size tracking wrapped around the sink use a plain `Rc<RefCell<_>>`
/// instead of an `Arc<Mutex<_>>` no thread ever actually contends.
pub fn decoder_for<'a>(
    compression: Compression,
    sink: impl tokio::io::AsyncWrite + Unpin + 'a,
) -> eyre::Result<Box<dyn tokio::io::AsyncWrite + Unpin + 'a>> {
    Ok(match compression {
        Compression::None => Box::new(sink),
        Compression::Zstd => Box::new(ZstdDecoder::new(sink)),
        Compression::Xz => Box::new(XzDecoder::new(sink)),
        Compression::Bzip2 => Box::new(BzDecoder::new(sink)),
        Compression::Gzip => Box::new(GzipDecoder::new(sink)),
        Compression::Lz4 => Box::new(Lz4Decoder::new(sink)),
        Compression::Brotli => Box::new(BrotliDecoder::new(sink)),
        // No viable Rust decoder exists for lzip -- named so it still
        // parses and logs correctly, but rejected here rather than
        // attempting a decode we cannot actually do.
        Compression::Lzip => bail!("lzip decoding is not supported"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_compression::tokio::write::{
        BrotliEncoder, BzEncoder, GzipEncoder, Lz4Encoder, XzEncoder, ZstdEncoder,
    };
    use tokio::io::AsyncWriteExt;

    const PLAINTEXT: &[u8] = b"kubernix decompress round-trip test payload, repeated a bit \
        kubernix decompress round-trip test payload, repeated a bit";

    macro_rules! round_trip_test {
        ($name:ident, $compression:expr, $encoder:ident) => {
            #[tokio::test]
            async fn $name() {
                let mut encoder = $encoder::new(Vec::new());
                encoder.write_all(PLAINTEXT).await.unwrap();
                encoder.shutdown().await.unwrap();
                let encoded = encoder.into_inner();

                let mut decoded = Vec::new();
                {
                    let mut decoder = decoder_for($compression, &mut decoded).unwrap();
                    decoder.write_all(&encoded).await.unwrap();
                    decoder.shutdown().await.unwrap();
                }

                assert_eq!(decoded, PLAINTEXT);
            }
        };
    }

    #[tokio::test]
    async fn none_round_trips() {
        let mut decoded = Vec::new();
        {
            let mut decoder = decoder_for(Compression::None, &mut decoded).unwrap();
            decoder.write_all(PLAINTEXT).await.unwrap();
            decoder.shutdown().await.unwrap();
        }
        assert_eq!(decoded, PLAINTEXT);
    }

    round_trip_test!(zstd_round_trips, Compression::Zstd, ZstdEncoder);
    round_trip_test!(xz_round_trips, Compression::Xz, XzEncoder);
    round_trip_test!(bzip2_round_trips, Compression::Bzip2, BzEncoder);
    round_trip_test!(gzip_round_trips, Compression::Gzip, GzipEncoder);
    round_trip_test!(lz4_round_trips, Compression::Lz4, Lz4Encoder);
    round_trip_test!(brotli_round_trips, Compression::Brotli, BrotliEncoder);

    #[tokio::test]
    async fn lzip_is_rejected() {
        let mut sink = Vec::new();
        assert!(decoder_for(Compression::Lzip, &mut sink).is_err());
    }
}
