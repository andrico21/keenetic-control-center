# Upstream items for andrico21/rust-guidelines

This repository does not open PRs against the guidelines repository. The owner upstreams
these by hand:

1. Add `overlays/projects/keenetic-control-center.md` (the file in this directory).
2. Add the README table row: `| keenetic-control-center | http-services, mcp-servers |`.
3. Propose an http-services clarification for operator-configured management targets in
   private address space (deviation 1 of the project overlay). Details below.

## Item 3: operator-configured management targets in private address space

**What the rule says.** The http-services overlay, "DO: Prevent SSRF" (lines 88-97),
says that when the server makes HTTP requests from user-supplied URLs it must allow
only `https` (or an explicit scheme allowlist), reject private, loopback and link-local
addresses, and reject `.local`, `.internal` and `.localhost` hostnames.

**Why a LAN manager needs an exception.** kcc manages Keenetic routers, which live on
private networks and are reached by a private address (over `http` or `https`, as the
project overlay allows). Every router target would be rejected by the rule as written. The target is not user-supplied in the SSRF
sense: only an administrator can create a router profile, and the address is fixed
configuration, not a request parameter.

**What kcc does instead** (`crates/kcc-rci/src/outbound.rs`, project overlay rule (a)):

- the operator lists the permitted networks in `[outbound] allowed_networks`; a target
  outside them is refused;
- cloud metadata addresses are refused regardless of that list;
- redirects are never followed, and TLS is verified or pinned, never skipped;
- each hostname is resolved once and the connection is pinned to that address, so a
  later DNS answer cannot move the request.

**Precedent.** `rmcp-server-kit` already carries the same idea for its OAuth client:
`OAuthSsrfAllowlist` lets the operator name hosts and networks that the SSRF checks
accept (`src/oauth.rs` and `src/ssrf.rs` in 3.21.1).

**What the proposal asks.** Add a short note to the http-services rule: the checks
apply to addresses a user or remote party chooses; a target that only an administrator
configures, in an explicit operator allowlist, with metadata addresses still refused,
redirects off and the resolved address pinned, may lie in private address space. The
note should name the allowlist as the required shape, so the exception is not read as
permission to widen outbound access.
