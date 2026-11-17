//! Router logs and background network diagnostics.

use alloc::sync::Arc;
use core::{result::Result as CoreResult, time::Duration};

use kcc_app::{
    jobs::{JobError, JobProgress, JobRunner, JobTarget},
    permissions::Permission,
};
use kcc_catalog::Risk;
use kcc_rci::{RciBody, RciClient, RciPath};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::{DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, descriptor};

/// Supported diagnostic process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DiagnosticKind {
    /// IPv4 ping.
    Ping,
    /// IPv6 ping.
    Ping6,
    /// Route trace.
    Traceroute,
    /// Address-resolution ping.
    Arping,
    /// Throughput measurement.
    Iperf3,
}

impl DiagnosticKind {
    /// Stable operation name.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Ping6 => "ping6",
            Self::Traceroute => "traceroute",
            Self::Arping => "arping",
            Self::Iperf3 => "iperf3",
        }
    }

    /// Catalog command path.
    #[inline]
    #[must_use]
    pub const fn catalog_path(self) -> &'static str {
        match self {
            Self::Ping => "tools ping",
            Self::Ping6 => "tools ping6",
            Self::Traceroute => "tools traceroute",
            Self::Arping => "tools arping",
            Self::Iperf3 => "tools iperf3",
        }
    }
}

/// Typed ping completion output.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct PingReply {
    /// Per-probe latency values.
    pub samples: Vec<Value>,
}

/// Typed traceroute hop.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct TraceHop {
    /// Hop number.
    pub hop: Option<u32>,
    /// Hop address.
    pub address: Option<String>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Typed ARP-ping reply.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ArpingReply {
    /// Responder address.
    pub address: Option<String>,
    /// Responder MAC.
    pub mac: Option<String>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Typed iperf3 completion output.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Iperf3Reply {
    /// Measured throughput.
    pub bits_per_second: Option<u64>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// One typed progress line emitted by a diagnostic process.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum ProgressLine {
    /// Ping latency.
    Ping(Value),
    /// IPv6 ping reply address.
    Ping6(String),
    /// Traceroute hop.
    Traceroute(TraceHop),
    /// ARP-ping result.
    Arping(ArpingReply),
    /// Iperf3 throughput result.
    Iperf3(Iperf3Reply),
}

/// Diagnostics read inventory.
const READS: &[OperationDescriptor] = &[OperationDescriptor {
    name: "system_log",
    catalog_path: "show log",
    risk: Risk::Read,
    permission: Permission::Read,
    persists_immediately: false,
}];

/// Diagnostics job inventory.
const WRITES: &[OperationDescriptor] = &[
    descriptor::read("ping", "tools ping"),
    descriptor::read("ping6", "tools ping6"),
    descriptor::read("traceroute", "tools traceroute"),
    descriptor::read("arping", "tools arping"),
    descriptor::read("iperf3", "tools iperf3"),
];

/// Diagnostics domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Diagnostics,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Reads the system log with the router's POST-only request shape.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]), or when a reply or a plan
/// does not have the expected shape ([`DomainError::InvalidResponse`]).
// cancel-safe: only reads the log; a dropped continuation poll leaves
// just a read-only request behind.
#[inline]
pub async fn read_log(client: &RciClient, max_lines: u32) -> Result<String> {
    let path =
        RciPath::from_segments(["show", "log"]).map_err(|_error| DomainError::InvalidResponse)?;
    let reply = client.post(&path, &json!({"max-lines":max_lines})).await?;
    match reply {
        RciBody::Text(text) => Ok(text),
        RciBody::Json(response) => {
            if response
                .value
                .get("continued")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                let handle = client.start(path, &json!({"max-lines":max_lines})).await?;
                let token = CancellationToken::new();
                match handle.poll(&token).await? {
                    RciBody::Text(text) => Ok(text),
                    RciBody::Json(done) => serde_json::to_string(&done.value)
                        .map_err(|_error| DomainError::InvalidResponse),
                    _ => Err(DomainError::InvalidResponse),
                }
            } else {
                serde_json::to_string(&response.value)
                    .map_err(|_error| DomainError::InvalidResponse)
            }
        }
        _ => Err(DomainError::InvalidResponse),
    }
}

/// How often a running diagnostic asks the router for its next replies; the router's own
/// tools answer at about this pace, so a faster poll only loads the router.
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Starts a diagnostic as a persisted non-write job.
///
/// # Errors
///
/// Returns [`JobError::IdUnavailable`] when no random job id can be drawn,
/// [`JobError::IdCollision`] when the drawn id is already claimed, and [`JobError::State`] when
/// the job's lock or its initial record cannot be stored. A failure of the diagnostic itself is
/// recorded on the job, not returned here.
// NOT cancel-safe: once spawned, the diagnostic job runs on without its id reaching the caller;
// cancelled inside job start, its ownership lock can stay held.
#[inline]
pub async fn start_job(
    jobs: &Arc<JobRunner>,
    router_name: String,
    client: Arc<RciClient>,
    kind: DiagnosticKind,
    body: Value,
) -> CoreResult<String, JobError> {
    jobs.start(
        format!("diagnostics.{}", kind.name()),
        JobTarget::Read(Some(router_name)),
        async move |context| {
            let path = RciPath::from_segments(["tools", kind.name()])
                .map_err(|_error| "invalid diagnostic path".to_owned())?;
            let handle = client
                .start(path, &body)
                .await
                .map_err(|error| error.to_string())?
                .with_poll_interval(POLL_INTERVAL);
            let completed = handle
                .poll(&context.cancellation())
                .await
                .map_err(|error| error.to_string())?;
            let RciBody::Json(response) = completed else {
                return Err("diagnostic returned text".to_owned());
            };
            for line in progress_lines(kind, response.value.get("reply").unwrap_or(&Value::Null)) {
                context.structured_progress(JobProgress::OutputLine(line));
            }
            context.progress(100);
            Ok(())
        },
    )
    .await
}

/// Converts a completed process reply into stable typed output lines.
#[must_use]
#[inline]
pub fn typed_progress(kind: DiagnosticKind, reply: &Value) -> Vec<ProgressLine> {
    match kind {
        DiagnosticKind::Ping => reply
            .as_array()
            .into_iter()
            .flatten()
            .cloned()
            .map(ProgressLine::Ping)
            .collect(),
        DiagnosticKind::Ping6 => reply
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .map(ProgressLine::Ping6)
            .collect(),
        DiagnosticKind::Traceroute => serde_json::from_value::<Vec<TraceHop>>(reply.clone())
            .unwrap_or_default()
            .into_iter()
            .map(ProgressLine::Traceroute)
            .collect(),
        DiagnosticKind::Arping => serde_json::from_value::<Vec<ArpingReply>>(reply.clone())
            .unwrap_or_default()
            .into_iter()
            .map(ProgressLine::Arping)
            .collect(),
        DiagnosticKind::Iperf3 => serde_json::from_value::<Iperf3Reply>(reply.clone())
            .ok()
            .into_iter()
            .map(ProgressLine::Iperf3)
            .collect(),
    }
}

/// Serializes typed progress into job output lines.
fn progress_lines(kind: DiagnosticKind, reply: &Value) -> Vec<String> {
    typed_progress(kind, reply)
        .into_iter()
        .filter_map(|line| serde_json::to_string(&progress_value(line)).ok())
        .collect()
}

/// Converts one typed progress item to structured JSON.
fn progress_value(line: ProgressLine) -> Value {
    match line {
        ProgressLine::Ping(value) => json!({"kind":"ping","sample":value}),
        ProgressLine::Ping6(address) => json!({"kind":"ping6","address":address}),
        ProgressLine::Traceroute(hop) => json!({"kind":"traceroute","hop":hop}),
        ProgressLine::Arping(reply) => json!({"kind":"arping","reply":reply}),
        ProgressLine::Iperf3(reply) => json!({"kind":"iperf3","reply":reply}),
    }
}
