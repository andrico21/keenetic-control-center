//! The running notifier as the Web administration page sees it.

use kcc_telemetry::notify::failure::SendError;
use kcc_web::admin_notify::{NotifyControl, NotifyStatus, NotifyTestError, TestSend};

use super::{NotifyHandle, current, render};

impl NotifyControl for NotifyHandle {
    fn status(&self) -> NotifyStatus {
        let outbox = self.shared.outbox.status();
        let status = NotifyStatus::new(outbox.queued, outbox.dropped);
        if outbox.token_rejected {
            status.with_token_rejected()
        } else {
            status
        }
    }

    // NOT cancel-safe: dropped after the request went out, the message may still arrive.
    fn send_test<'send>(&'send self, chat: &'send str) -> TestSend<'send> {
        Box::pin(async move {
            let settings = current::reload(&self.shared)
                .await
                .ok_or(NotifyTestError::Unreachable)?;
            let target = settings
                .chats
                .as_slice()
                .iter()
                .find(|listed| listed.id.as_str() == chat)
                .cloned()
                .ok_or(NotifyTestError::ChatRefused)?;
            let text = render::test(self.shared.locale());
            self.shared
                .outbox
                .send_now(target, text)
                .await
                .map_err(test_error)
        })
    }

    fn reload(&self) {
        self.shared.reloads.send_replace(());
    }
}

/// The class of a failed test message.
#[expect(
    clippy::match_same_arms,
    reason = "every known class is listed; the wildcard covers classes added later"
)]
const fn test_error(error: SendError) -> NotifyTestError {
    match error {
        SendError::NotConfigured => NotifyTestError::NoToken,
        SendError::TokenRejected => NotifyTestError::TokenRejected,
        SendError::ChatUnavailable(_) => NotifyTestError::ChatRefused,
        SendError::RetryAfter(_) => NotifyTestError::RateLimited,
        SendError::Rejected => NotifyTestError::Rejected,
        SendError::Transient { status: _ }
        | SendError::AddressRefused
        | SendError::CaFile
        | SendError::Certificate
        | SendError::Client
        | SendError::Stopped => NotifyTestError::Unreachable,
        _ => NotifyTestError::Unreachable,
    }
}
