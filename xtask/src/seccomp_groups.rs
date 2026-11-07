//! The fixed group map of `deploy/podman/seccomp-kcc.json`.
//!
//! Every syscall the traced binary makes must be listed in exactly one group; an unmapped
//! syscall fails `cargo xtask seccomp gen` until it is assigned here with a rationale.
//! Groups render in this order and only with the names that were traced (plus the
//! container-runtime prologue and the cross-architecture equivalents below).

/// One rationale group of allowed syscalls: the `_group` text and every name it may hold.
pub(crate) type Group = (&'static str, &'static [&'static str]);

/// The allowed groups, in profile order.
pub(crate) const GROUPS: &[Group] = &[
    (
        "process and thread lifecycle: the static musl runtime, tokio's worker threads (futex, rseq, robust lists) and process identity reads",
        &[
            "arch_prctl", "execve", "exit", "exit_group", "futex", "getegid", "geteuid",
            "getgid", "getpid", "getppid", "getresgid", "getresuid", "gettid", "getuid",
            "membarrier", "prlimit64", "restart_syscall", "rseq", "sched_getaffinity",
            "sched_yield", "set_robust_list", "set_tid_address", "uname",
        ],
    ),
    (
        "privilege floor (kcc::privileges::enforce): capget/capset clear the capability sets and prctl drops the bounding and ambient sets and sets no_new_privs. None of them can raise a capability: the container's permitted set is empty",
        &["capget", "capset", "prctl"],
    ),
    (
        "memory",
        &["brk", "madvise", "mmap", "mprotect", "mremap", "munmap"],
    ),
    (
        "signals: tokio's SIGTERM/SIGINT/SIGHUP handlers and the alternate signal stack of every thread",
        &["rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack"],
    ),
    (
        "file reads: kcc.toml, the mounted secrets (master key, TLS pair, router passwords), /proc/self/status, /etc/hosts and /etc/resolv.conf, the CA bundle; ioctl is the terminal probe (TCGETS/TIOCGWINSZ) of the CLI output",
        &[
            "access", "close", "faccessat", "faccessat2", "fcntl", "fstat", "getcwd",
            "getdents64", "ioctl", "lseek", "newfstatat", "open", "openat", "pread64", "read",
            "readlink", "readlinkat", "readv", "stat", "statx", "lstat",
        ],
    ),
    (
        "state writes inside the /var/lib/kcc volume: encrypted stores written 0600 through a temporary file, fsync and rename, advisory flock locks, audit appends, backups and plans",
        &[
            "chmod", "dup", "dup2", "dup3", "fchmod", "fchmodat", "fdatasync", "flock",
            "fsync", "ftruncate", "link", "linkat", "mkdir", "mkdirat", "pwrite64", "rename",
            "renameat", "renameat2", "rmdir", "umask", "unlink", "unlinkat", "write", "writev",
        ],
    ),
    (
        "sockets: the TLS listener and the metrics listener, outbound HTTP to routers and log sinks, and the musl DNS resolver. getsockopt completes every non-blocking connect (SO_ERROR): without it every router request fails while the listeners stay healthy",
        &[
            "accept", "accept4", "bind", "connect", "getpeername", "getsockname",
            "getsockopt", "listen", "recvfrom", "recvmmsg", "recvmsg", "sendmmsg", "sendmsg",
            "sendto", "setsockopt", "shutdown", "socket", "socketpair",
        ],
    ),
    (
        "event loop and timers: tokio's epoll reactor and its eventfd waker, the musl resolver's poll, and the clocks behind timeouts, sessions and poll cadences",
        &[
            "clock_getres", "clock_gettime", "clock_nanosleep", "epoll_create", "epoll_create1",
            "epoll_ctl", "epoll_pwait", "epoll_pwait2", "epoll_wait", "eventfd2",
            "gettimeofday", "nanosleep", "pipe", "pipe2", "poll", "ppoll", "pselect6", "select",
        ],
    ),
    (
        "entropy: session ids, CSRF tokens, API keys and AES-GCM nonces come from the kernel CSPRNG",
        &["getrandom"],
    ),
];

/// The container-runtime exec prologue.
///
/// Syscalls crun or runc make after installing the filter and before the exec of `/kcc`
/// completes; allowed although a native trace of the binary cannot see them.
pub(crate) const PROLOGUE: &[&str] = &[
    "capget", "capset", "close", "close_range", "execve", "fstat", "newfstatat", "prctl",
];

/// The group rationale of the prologue-only names.
pub(crate) const PROLOGUE_RATIONALE: &str = "container runtime exec prologue: syscalls crun/runc make between installing this filter and the exec of /kcc (closing inherited descriptors, the final capability set, execve); not visible to a native trace";

/// Cross-architecture equivalents.
///
/// The trace runs on `x86_64`, whose legacy syscalls have generic replacements on
/// `aarch64` (which lacks the legacy ones). Each traced name on the left also allows the
/// names on the right.
pub(crate) const EQUIVALENTS: &[(&str, &[&str])] = &[
    ("access", &["faccessat", "faccessat2"]),
    ("dup2", &["dup3"]),
    ("epoll_create", &["epoll_create1"]),
    ("epoll_wait", &["epoll_pwait"]),
    ("link", &["linkat"]),
    ("lstat", &["newfstatat"]),
    ("mkdir", &["mkdirat"]),
    ("open", &["openat"]),
    ("pipe", &["pipe2"]),
    ("poll", &["ppoll"]),
    ("readlink", &["readlinkat"]),
    ("rename", &["renameat", "renameat2"]),
    ("rmdir", &["unlinkat"]),
    ("select", &["pselect6"]),
    ("stat", &["newfstatat"]),
    ("unlink", &["unlinkat"]),
];

/// Rationale of the filtered `clone` rule.
pub(crate) const CLONE_RATIONALE: &str = "thread creation with namespace flags denied. clone's flags are a register value, so seccomp can test them: this permits musl's pthread_create and refuses CLONE_NEWUSER and its siblings. 2114060288 is 0x7E020000 = NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET";

/// The namespace flags `clone` must not carry.
pub(crate) const CLONE_NAMESPACE_FLAGS: u64 = 0x7E02_0000;

/// Rationale of the `clone3` rule.
pub(crate) const CLONE3_RATIONALE: &str = "clone3 passes its flags behind a pointer that seccomp cannot dereference, so the clone filter cannot be expressed for it. ENOSYS (38) rather than EPERM makes any caller fall back to clone; the static musl binary never calls it";

/// `ENOSYS`.
pub(crate) const ENOSYS: u32 = 38;
