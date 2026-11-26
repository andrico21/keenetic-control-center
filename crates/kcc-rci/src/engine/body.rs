//! Bounded response-body reads into buffers wiped on drop.

use reqwest::Response;
use zeroize::Zeroizing;

use crate::{RciError, TransportCause};

/// Reads at most `cap` bytes into a buffer wiped on drop.
///
/// The buffer is reserved at the announced length (never above `cap`). A body that
/// outgrows it moves into a larger buffer and the old one is wiped, so no reallocation
/// leaves a copy of the body in freed memory.
///
/// # Errors
///
/// Returns transport or body-size errors.
// cancel-safe: partial body bytes are local state, wiped on drop.
pub(crate) async fn read_capped(
    mut response: Response,
    cap: usize,
) -> Result<Zeroizing<Vec<u8>>, RciError> {
    let announced = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .map_or(0, |length| length.min(cap));
    let mut body = Zeroizing::new(Vec::with_capacity(announced));
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        if error.is_timeout() {
            RciError::Timeout
        } else {
            RciError::Transport(TransportCause::BodyInterrupted)
        }
    })? {
        let needed = body.len().saturating_add(chunk.len());
        if needed > cap {
            return Err(RciError::BodyTooLarge);
        }
        if needed > body.capacity() {
            let size = needed.max(body.capacity().saturating_mul(2)).min(cap);
            let mut grown = Zeroizing::new(Vec::with_capacity(size));
            grown.extend_from_slice(&body);
            body = grown;
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use alloc::collections::VecDeque;
    use core::{
        convert::Infallible,
        pin::Pin,
        task::{Context, Poll},
    };

    use hyper::body::{Body, Bytes, Frame, SizeHint};

    use super::read_capped;
    use crate::RciError;

    /// A response body arriving in the given chunks, announcing `exact` bytes.
    struct Chunks {
        /// Chunks still to deliver.
        left: VecDeque<Bytes>,
        /// The announced length, as a `Content-Length` header would give it.
        exact: Option<u64>,
    }

    impl Body for Chunks {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            Poll::Ready(self.left.pop_front().map(|chunk| Ok(Frame::data(chunk))))
        }

        fn size_hint(&self) -> SizeHint {
            self.exact
                .map_or_else(SizeHint::default, SizeHint::with_exact)
        }
    }

    /// A response delivering `chunks`, announcing `exact` bytes.
    fn response(chunks: &[&'static [u8]], exact: Option<u64>) -> reqwest::Response {
        let body = Chunks {
            left: chunks.iter().copied().map(Bytes::from_static).collect(),
            exact,
        };
        reqwest::Response::from(hyper::Response::new(reqwest::Body::wrap(body)))
    }

    const PARTS: [&[u8]; 3] = [b"! $$$ Model", b": test\nsyst", b"em name x\n"];

    /// SEC2-16, A-10: a body whose length is announced is read into one buffer reserved
    /// at that size, so no reallocation leaves a copy of a downloaded configuration in
    /// freed memory.
    #[tokio::test]
    async fn announced_body_fills_one_buffer_of_its_size() -> Result<(), RciError> {
        let length = PARTS.iter().map(|part| part.len()).sum::<usize>();
        let body = read_capped(response(&PARTS, u64::try_from(length).ok()), 4096).await?;
        assert_eq!(body.as_slice(), PARTS.concat().as_slice(), "content");
        assert_eq!(
            body.capacity(),
            length,
            "one allocation of the announced size"
        );
        Ok(())
    }

    /// A body without a length keeps its order across growth, and a huge announced length
    /// reserves no more than the cap.
    #[tokio::test]
    async fn growth_and_lying_lengths_keep_the_content() -> Result<(), RciError> {
        for exact in [None, Some(u64::MAX)] {
            let body = read_capped(response(&PARTS, exact), 64).await?;
            assert_eq!(body.as_slice(), PARTS.concat().as_slice(), "content");
            assert!(body.capacity() <= 64, "never more than the cap");
        }
        let refused = read_capped(response(&PARTS, None), 16).await;
        assert!(
            matches!(refused, Err(RciError::BodyTooLarge)),
            "over the cap"
        );
        Ok(())
    }
}
