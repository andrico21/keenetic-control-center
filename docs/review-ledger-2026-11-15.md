# Review ledger 2026-11-15

This ledger maps every validated finding of the 2026-11-15 full review (taken at HEAD `349b7fb`) to the commit on `master` that closed it, one row per finding. The finding ids come from `.omo/reviews/kcc-full-review-2026-11-15/VALIDATED.md`, including the critic-raised N-items and H4a. The note says in plain words how the finding was closed and names the plan todo whose commit closed it; "no behavioural test" marks a structural, dead-code or documentation fix that no regression test names.

The ledger is checked by `python3 .omo/reviews/kcc-full-review-2026-11-15/check_coverage.py docs/review-ledger-2026-11-15.md`: every expected id appears exactly once with a commit that exists. Refuted findings are not listed.

| finding id | commit | note |
| --- | --- | --- |
| A-01 | a040ba24 | fixed, regression test names it (todo 6) |
| A-02 | c9722278 | fixed, regression test names it (todo 39) |
| A-03 | 5ce65c77 | fixed, regression test names it (todo 40) |
| A-04 | 5ce65c77 | fixed, regression test names it (todo 40) |
| A-05 | 5ce65c77 | fixed, regression test names it (todo 40) |
| A-06 | 96f0bde6 | fixed, regression test names it (todo 42) |
| A-07 | 9d3a010c | fixed, regression test names it (todo 35) |
| A-08 | 9ad8b7d4 | fixed by structure; a test names it (todo 41) |
| A-09 | c9722278 | fixed, regression test names it (todo 39) |
| A-10 | 187d183f | fixed, regression test names it (todo 23) |
| A-11 | 9ad8b7d4 | fixed, regression test names it (todo 41) |
| A-12 | 5ce65c77 | fixed, regression test names it (todo 40) |
| A-13 | b55accfe | fixed, regression test names it (todo 20) |
| A-14 | c9722278 | fixed, regression test names it (todo 39) |
| A-15 | c9722278 | fixed, regression test names it (todo 39) |
| A-16 | 5ce65c77 | copies merged into one owner; no behavioural test (todo 40) |
| A-17 | 5ce65c77 | dead code removed; no behavioural test (todo 40) |
| A-18 | 51b16a94 | fixed by structure; no behavioural test (todo 66) |
| A-19 | 5ce65c77 | fixed by structure; a test names it (todo 40) |
| A-20 | 9ad8b7d4 | fixed by structure; a test names it (todo 41) |
| A-21 | 6280c5ea | tests reworked (test-only change) (todo 69) |
| A-22 | 6280c5ea | review-process labels removed from tests and comments (comment-only edits); no behavioural test (todo 69) |
| B-01 | 0727582b | fixed, regression test names it (todo 27) |
| B-02 | e6eff40c | fixed, regression test names it (todo 31) |
| B-03 | 0727582b | fixed, regression test names it (todo 27) |
| B-04 | 14a763e4 | fixed, regression test names it (todo 28) |
| B-05 | 0e73cdcb | fixed, regression test names it (todo 16) |
| B-06 | 9d3a010c | fixed, regression test names it (todo 35) |
| B-07 | fbab75b7 | fixed by structure; a test names it (todo 37) |
| B-08 | 034ec919 | fixed, regression test; second commit of the todo (the first, 9eedbb79, closed C-07 and D-15) (todo 8) |
| B-09 | f2ef9f53 | fixed, regression test names it (todo 36) |
| B-10 | f2ef9f53 | fixed by structure; a test names it (todo 36) |
| B-11 | 6d3d445a | fixed by structure; no behavioural test (todo 65) |
| B-12 | 96e058df | fixed by structure; a test names it (todo 12) |
| B-13 | 6d3d445a | fixed by structure; a test names it (todo 65) |
| B-14 | 0727582b | dead code removed; no behavioural test (todo 27) |
| B-15 | 14a763e4 | retention rustdoc corrected to the real behaviour (whole rotated files, at rotation) (todo 28) |
| B-16 | 6d3d445a | fixed by structure; no behavioural test (todo 65) |
| B-17 | 9d3a010c | fixed, regression test names it (todo 35) |
| B-18 | 51b16a94 | fixed by structure; no behavioural test (todo 66) |
| B-19 | f2ef9f53 | typed JobTarget makes a write job without a router unrepresentable; no behavioural test (todo 36) |
| B-20 | 14a763e4 | fixed by structure; a test names it (todo 28) |
| B-21 | f2ef9f53 | fixed, regression test names it (todo 36) |
| B-22 | 6d3d445a | fixed by structure; a test names it (todo 65) |
| B-23 | 6280c5ea | tests reworked; a test names it (todo 69) |
| B-24 | 6d3d445a | fixed, regression test names it (todo 65) |
| C-01 | b7e853d5 | fixed, regression test names it (todo 9) |
| C-02 | e6eff40c | fixed, regression test names it (todo 31) |
| C-03 | 623266de | fixed, regression test names it (todo 32) |
| C-04 | a040ba24 | fixed, regression test names it (todo 6) |
| C-05 | e6237723 | fixed by structure; a test names it (todo 11) |
| C-06 | e6237723 | fixed, regression test names it (todo 11) |
| C-07 | 9eedbb79 | fixed, regression test; first commit of the todo (B-08 closed by 034ec919) (todo 8) |
| C-08 | d9c62fa5 | fixed, regression test names it (todo 48) |
| C-09 | d9c62fa5 | fixed, regression test names it (todo 48) |
| C-10 | 3ddf29a4 | partition check/format removed from domain, MCP, CLI and Web (format dialog route now 404); regression test (todo 52) |
| C-11 | 623266de | fixed, regression test names it (todo 32) |
| C-12 | e6237723 | fixed, regression test names it (todo 11) |
| C-13 | 96e058df | fixed by one error vocabulary; no behavioural test (disclosed in the commit: covered structurally) (todo 12) |
| C-14 | 3ddf29a4 | fixed by structure; no behavioural test (todo 52) |
| C-15 | 623266de | fixed, regression test names it (todo 32) |
| C-16 | 623266de | close rustdoc corrected (a failed keep-unsaved ends Applied) (todo 32) |
| C-17 | 3ddf29a4 | copies merged into one owner; no behavioural test (todo 52) |
| C-18 | 3ddf29a4 | dead and test-only code removed (registry dump differs only by the removed operations); no behavioural test (todo 52) |
| C-19 | d2d695b7 | fixed by structure; a test names it (todo 38) |
| C-20 | b7e853d5 | fixed, regression test names it (todo 9) |
| C-21 | 623266de | fixed by structure; a test names it (todo 32) |
| C-22 | 48188cc5 | fixed, regression test names it (todo 53) |
| C-23 | d9c62fa5 | fixed, regression test names it (todo 48) |
| C-24 | ded8bd1f | fixed, regression test names it (todo 19) |
| C-25 | 6280c5ea | tests reworked; a test names it (todo 69) |
| D-01 | 846c9150 | fixed, regression test names it (todo 2) |
| D-02 | b7e853d5 | fixed, regression test names it (todo 9) |
| D-03 | 65f93954 | fixed, regression test names it (todo 49) |
| D-04 | 0834658f | fixed, regression test names it (todo 50) |
| D-05 | 65f93954 | fixed, regression test names it (todo 49) |
| D-06 | 65f93954 | fixed, regression test names it (todo 49) |
| D-07 | 65f93954 | not changed in code: documented as a known limit in rustdoc and BACKLOG (binding critic correction) (todo 49) |
| D-08 | 0834658f | fixed, regression test names it (todo 50) |
| D-09 | 0834658f | fixed, regression test names it (todo 50) |
| D-10 | 65f93954 | fixed by structure; a test names it (todo 49) |
| D-11 | 49f5f14e | fixed, regression test names it (todo 51) |
| D-12 | 49f5f14e | fixed, regression test names it (todo 51) |
| D-13 | 3ddf29a4 | copies merged into one owner; no behavioural test (todo 52) |
| D-14 | 588a6795 | unused vpn-server RevealSecrets gate and its tests deleted (dead code) (todo 26) |
| D-15 | 9eedbb79 | fixed, regression test; first commit of the todo (B-08 closed by 034ec919) (todo 8) |
| D-16 | 49f5f14e | fixed, regression test names it (todo 51) |
| D-17 | 49f5f14e | fixed, regression test names it (todo 51) |
| D-18 | 96e058df | fixed; policy/NAT/segment read-backs covered structurally only (disclosed in the commit) (todo 12) |
| D-19 | 3ddf29a4 | copies merged into one owner; no behavioural test (todo 52) |
| D-20 | 0834658f | fixed, regression test names it (todo 50) |
| D-21 | 3ddf29a4 | fixed by structure; a test names it (todo 52) |
| D-22 | 3ddf29a4 | fixed by structure; a test names it (todo 52) |
| D-23 | 6280c5ea | tests reworked; a test names it (todo 69) |
| E-01 | 757b48b1 | decision D-H1: MCP denylist replaced by the shared masker (a040ba24), text bodies redacted here; regression test (todo 7) |
| E-02 | 055788ef | fixed, regression test names it (todo 25) |
| E-03 | 01e27518 | fixed, regression test: lease released at the end of the recovery window, records evicted; no cross-identity finish (todo 33) |
| E-04 | ccaaaad1 | fixed, regression test names it (todo 43) |
| E-05 | b4e941f1 | fixed, regression test names it (todo 44) |
| E-06 | 01e27518 | fixed by structure; a test names it (todo 33) |
| E-07 | 96e058df | fixed, regression test names it (todo 12) |
| E-08 | 2a5255e7 | fixed, regression test names it (todo 30) |
| E-09 | 2a5255e7 | fixed by structure; a test names it (todo 30) |
| E-10 | 5c9e70ca | fixed by structure; no behavioural test (todo 47) |
| E-11 | 51b16a94 | fixed by structure; no behavioural test (todo 66) |
| E-12 | ccaaaad1 | fixed by structure; a test names it (todo 43) |
| E-13 | b4e941f1 | fixed, regression test names it (todo 44) |
| E-14 | 5c9e70ca | fixed by structure; a test names it (todo 47) |
| E-15 | 96e058df | fixed by structure; no behavioural test (todo 12) |
| E-16 | 96e058df | fixed by structure; no behavioural test (todo 12) |
| E-17 | 96e058df | fixed by structure; a test names it (todo 12) |
| E-18 | ccaaaad1 | fixed by structure; a test names it (todo 43) |
| E-19 | 96e058df | fixed, regression test names it (todo 12) |
| E-20 | ccaaaad1 | fixed, regression test names it (todo 43) |
| E-22 | 9ad8b7d4 | fixed by structure; a test names it (todo 41) |
| E-23 | 6280c5ea | tests reworked; a test names it (todo 69) |
| E-24 | 2a5255e7 | fixed by structure; a test names it (todo 30) |
| F-01 | 59a18c4f | H7, decision D-H7: 2 s state watcher and SIGHUP reload keys and end stale sessions; regression test (todo 5) |
| F-02 | 57489daa | fixed, regression test names it (todo 17) |
| F-03 | 7365209e | fixed, regression test names it (todo 13) |
| F-04 | 757b48b1 | closed with H1 (D-H1): CLI show/rci replies redacted without RevealSecrets; regression test (todo 7) |
| F-05 | 6ffe4bbd | fixed, regression test names it (todo 63) |
| F-06 | 588a6795 | fixed, regression test names it (todo 26) |
| F-07 | 255b7bf5 | fixed, regression test names it (todo 61) |
| F-08 | a040ba24 | copies merged into one owner; no behavioural test (todo 6) |
| F-09 | df2fb8ff | fixed by structure; a test names it (todo 62) |
| F-10 | 633e93e1 | fixed by structure; a test names it (todo 64) |
| F-11 | d9c62fa5 | fixed, regression test names it (todo 48) |
| F-12 | 255b7bf5 | fixed, regression test names it (todo 61) |
| F-13 | 2a5255e7 | fixed, regression test names it (todo 30) |
| F-14 | 187d183f | fixed by structure; a test names it (todo 23) |
| F-15 | 255b7bf5 | fixed, regression test names it (todo 61) |
| F-16 | 255b7bf5 | VPN secret writes take gate and unsaved flag from the plan; behaviour unchanged, no new test (todo 61) |
| F-17 | 57489daa | fixed, regression test names it (todo 17) |
| F-18 | df2fb8ff | fixed by structure; a test names it (todo 62) |
| F-19 | efe9b08a | privilege report kept and logged after tracing starts; no behavioural test (todo 24) |
| F-20 | df2fb8ff | fixed by structure; no behavioural test (todo 62) |
| F-21 | df2fb8ff | fixed by structure; no behavioural test (todo 62) |
| F-22 | 5e940bf4 | fixed, regression test names it (todo 22) |
| F-23 | df2fb8ff | fixed, regression test names it (todo 62) |
| F-24 | df2fb8ff | fixed by structure; no behavioural test (todo 62) |
| F-25 | 14a763e4 | fixed by structure; a test names it (todo 28) |
| F-26 | df2fb8ff | removed `kcc diagnostics log` and the ppp kind of `kcc vpn secret`; --help diff checked; no test (todo 62) |
| F-27 | 255b7bf5 | fixed, regression test names it (todo 61) |
| F-28 | 255b7bf5 | fixed, regression test names it (todo 61) |
| F-29 | 6280c5ea | tests reworked (test-only change) (todo 69) |
| F-30 | 6280c5ea | tests reworked (test-only change) (todo 69) |
| F-31 | bddeeb8f | fixed by structure; a test names it (todo 68) |
| G-01 | b57d6e95 | fixed, regression test names it (todo 3) |
| G-02 | 055788ef | fixed, regression test names it (todo 25) |
| G-03 | ccdb1272 | fixed, regression test names it (todo 4) |
| G-04 | ccdb1272 | fixed, regression test; a Mirror-only guard was dropped (no observable effect on the fake catalog) (todo 4) |
| G-05 | 623266de | fixed, regression test names it (todo 32) |
| G-06 | a92452ac | fixed, regression test names it (todo 54) |
| G-08 | 93f43e36 | fixed, regression test names it (todo 45) |
| G-09 | 93f43e36 | fixed, regression test names it (todo 45) |
| G-10 | 93f43e36 | fixed, regression test names it (todo 45) |
| G-11 | 93f43e36 | fixed, regression test names it (todo 45) |
| G-12 | 93f43e36 | fixed, regression test names it (todo 45) |
| G-13 | 93f43e36 | fixed by structure; a test names it (todo 45) |
| G-14 | b55accfe | unused policy-bypassing entry points deleted (MigrationSource, load_source, connect); no behavioural test (todo 20) |
| G-15 | a92452ac | fixed by structure; a test names it (todo 54) |
| G-16 | ceac6158 | fixed, regression test names it (todo 46) |
| G-17 | b4e941f1 | fixed, regression test names it (todo 44) |
| G-18 | ceac6158 | fixed by structure; a test names it (todo 46) |
| G-19 | ceac6158 | fixed, regression test names it (todo 46) |
| G-20 | 51b16a94 | fixed by structure; no behavioural test (todo 66) |
| G-21 | a92452ac | fixed by structure; a test names it (todo 54) |
| G-22 | fbab75b7 | fixed by structure; a test names it (todo 37) |
| G-23 | a92452ac | test-only ContinueOnNonCritical path and StopPolicy removed; first-rejected-line stop stays covered (todo 54) |
| G-24 | 93f43e36 | fixed, regression test names it (todo 45) |
| G-25 | 6280c5ea | tests reworked (test-only change) (todo 69) |
| SEC1-01 | 757b48b1 | decision D-H1: reads redacted by the shared masker unless RevealSecrets on the router; regression test (todo 7) |
| SEC1-02 | d4584665 | fixed, regression test names it (todo 1) |
| SEC1-03 | 7365209e | fixed, regression test names it (todo 13) |
| SEC1-04 | a040ba24 | fixed by structure; a test names it (todo 6) |
| SEC1-05 | 59a18c4f | closed with F-01 (H7): watcher ends sessions of disabled or reset accounts; not named in the commit body (todo 5) |
| SEC1-06 | 87aef588 | fixed, regression test names it (todo 14) |
| SEC1-07 | fe10c729 | fixed, regression test names it (todo 15) |
| SEC1-08 | 788bb0ad | fixed, regression test names it (todo 29) |
| SEC1-09 | 57489daa | fixed, regression test names it (todo 17) |
| SEC1-10 | 77a48a05 | fixed by structure: private Rendered newtype and an assets-check rule, no askama safe filter left; test names it (todo 56) |
| SEC1-11 | 0e73cdcb | fixed, regression test names it (todo 16) |
| SEC1-12 | fe10c729 | fixed, regression test names it (todo 15) |
| SEC1-13 | 91fcdce3 | app.js labels dropped, one beforeSwap handler; old and new compared in a node vm harness, no committed test (todo 58) |
| SEC1-14 | 588a6795 | fixed, regression test names it (todo 26) |
| SEC2-01 | b55accfe | fixed, regression test names it (todo 20) |
| SEC2-02 | b7e853d5 | fixed, regression test names it (todo 9) |
| SEC2-03 | 9d3a010c | fixed, regression test names it (todo 35) |
| SEC2-04 | 0727582b | fixed, regression test names it (todo 27) |
| SEC2-05 | 0727582b | fixed, regression test names it (todo 27) |
| SEC2-06 | b55accfe | fixed, regression test names it (todo 20) |
| SEC2-07 | a040ba24 | fixed, regression test names it (todo 6) |
| SEC2-09 | b55accfe | fixed by structure; a test names it (todo 20) |
| SEC2-10 | b55accfe | fixed, regression test names it (todo 20) |
| SEC2-11 | b55accfe | fixed, regression test names it (todo 20) |
| SEC2-12 | 0e73cdcb | fixed, regression test names it (todo 16) |
| SEC2-13 | 5e940bf4 | fixed by structure; a test names it (todo 22) |
| SEC2-14 | 93f43e36 | fixed, regression test names it (todo 45) |
| SEC2-15 | c35b10be | fixed by structure; a test names it (todo 21) |
| SEC2-16 | 187d183f | fixed by structure; a test names it (todo 23) |
| SEC2-17 | 5e940bf4 | fixed, regression test names it (todo 22) |
| SEC2-18 | c35b10be | fixed, regression test names it (todo 21) |
| SEC2-19 | efe9b08a | fixed, regression test names it (todo 24) |
| SEC2-20 | 5e940bf4 | fixed, regression test names it (todo 22) |
| T-01 | 590115c1 | tests reworked; a test names it (todo 67) |
| T-02 | bddeeb8f | tests reworked; a test names it (todo 68) |
| T-03 | 590115c1 | fixed, regression test names it (todo 67) |
| T-04 | 590115c1 | tests reworked; a test names it (todo 67) |
| T-05 | bddeeb8f | fixed, regression test names it (todo 68) |
| T-06 | bddeeb8f | live_mcp_smoke installs a tracing subscriber; proved by a scratch run, not by a committed test (todo 68) |
| T-07 | 6280c5ea | tests reworked; a test names it (todo 69) |
| T-08 | bddeeb8f | fixed by structure; a test names it (todo 68) |
| T-09 | bddeeb8f | tests reworked; a test names it (todo 68) |
| T-10 | 6280c5ea | fixed by structure; a test names it (todo 69) |
| T-11 | 6280c5ea | tests reworked (test-only change) (todo 69) |
| T-12 | 6280c5ea | tests reworked (test-only change) (todo 69) |
| W1-01 | 59a18c4f | closed with F-01 (H7): watcher ends sessions of disabled or password-changed accounts; not named in commit body (todo 5) |
| W1-02 | 87aef588 | fixed, regression test names it (todo 14) |
| W1-03 | fe10c729 | fixed, regression test names it (todo 15) |
| W1-04 | 0e73cdcb | fixed, regression test names it (todo 16) |
| W1-05 | 57489daa | fixed, regression test names it (todo 17) |
| W1-06 | 0a19fc1a | fixed, regression test names it (todo 18) |
| W1-07 | ded8bd1f | fixed, regression test names it (todo 19) |
| W1-08 | 788bb0ad | fixed by structure; a test names it (todo 29) |
| W1-09 | 91fcdce3 | fixed by structure; a test names it (todo 58) |
| W1-10 | 91fcdce3 | todo labels dropped from app.js, behaviour sentences kept; no behavioural test (todo 58) |
| W1-11 | 91fcdce3 | fixed by structure; a test names it (todo 58) |
| W1-12 | 91fcdce3 | fixed by structure; no behavioural test (todo 58) |
| W1-13 | 0e73cdcb | fixed by structure; a test names it (todo 16) |
| W1-14 | 7365209e | binding critic correction: recorded as overlay deviation 5 plus an upstream BACKLOG item; no code change (todo 13) |
| W1-15 | 0a19fc1a | fixed, regression test names it (todo 18) |
| W1-16 | 91fcdce3 | fixed, regression test names it (todo 58) |
| W1-17 | 588a6795 | fixed, regression test names it (todo 26) |
| W1-18 | 91fcdce3 | tests reworked; a test names it (todo 58) |
| W2-01 | 95a9b4f3 | fixed, regression test names it (todo 10) |
| W2-02 | 01e27518 | fixed, regression test names it (todo 33) |
| W2-03 | 2a5255e7 | fixed, regression test names it (todo 30) |
| W2-05 | 95a9b4f3 | fixed, regression test names it (todo 10) |
| W2-06 | b9b80411 | fixed by structure; a test names it (todo 57) |
| W2-07 | d2d695b7 | fixed by structure; a test names it (todo 38) |
| W2-08 | fbab75b7 | fixed by structure; a test names it (todo 37) |
| W2-09 | b9b80411 | fixed, regression test names it (todo 57) |
| W2-10 | 2a5255e7 | fixed, regression test names it (todo 30) |
| W2-11 | b9b80411 | fixed by structure; a test names it (todo 57) |
| W2-12 | b9b80411 | fixed by structure; a test names it (todo 57) |
| W2-14 | b9b80411 | tests reworked; a test names it (todo 57) |
| W2-15 | 77a48a05 | fixed by structure: private Rendered newtype plus HtmlSafe marker (not a field allowlist), no safe filter; test (todo 56) |
| W2-16 | b9b80411 | fixed by structure; no behavioural test (todo 57) |
| W2-17 | b9b80411 | fixed by structure; no behavioural test (todo 57) |
| W2-18 | b9b80411 | dead template calls dropped; Action::run refuses Change::Batch at run time (variant kept); no test (todo 57) |
| W3-01 | 95a9b4f3 | fixed, regression test names it (todo 10) |
| W3-02 | 95a9b4f3 | fixed, regression test names it (todo 10) |
| W3-04 | d9c62fa5 | fixed, regression test names it (todo 48) |
| W3-05 | a90e10ff | fixed by structure; a test names it (todo 55) |
| W3-06 | 96e058df | fixed by structure; a test names it (todo 12) |
| W3-07 | 95a9b4f3 | tests reworked; a test names it (todo 10) |
| W3-08 | 65f93954 | fixed by structure; a test names it (todo 49) |
| W3-09 | 96e058df | fixed by structure; a test names it (todo 12) |
| W3-10 | a90e10ff | copies merged into one owner; no behavioural test (todo 55) |
| W3-11 | a90e10ff | copies merged into one owner; no behavioural test (todo 55) |
| W3-13 | a90e10ff | fixed, regression test names it (todo 55) |
| W3-14 | a90e10ff | fixed by structure; no behavioural test (todo 55) |
| W3-15 | a90e10ff | misleading doc path and dead bits corrected (DHCP sub-item dropped by the critic) (todo 55) |
| W3-16 | a90e10ff | tests reworked; a test names it (todo 55) |
| W3-17 | 77a48a05 | fixed by structure: composed regions are typed Rendered, no safe filter; the assets-check rule test names it (todo 56) |
| W4-01 | 757b48b1 | decision D-H1: explorer and console reads redacted without RevealSecrets; regression test (todo 7) |
| W4-02 | 588a6795 | fixed, regression test names it (todo 26) |
| W4-03 | ded8bd1f | fixed, regression test names it (todo 19) |
| W4-05 | ded8bd1f | fixed by structure; a test names it (todo 19) |
| W4-06 | 95a9b4f3 | six comments corrected: management changes do not need Destructive (todo 10) |
| W4-07 | d2d695b7 | fixed, regression test names it (todo 38) |
| W4-08 | dcdb6367 | fixed, regression test names it (todo 59) |
| W4-09 | 187d183f | fixed by structure; a test names it (todo 23) |
| W4-10 | dcdb6367 | copies merged into one owner; no behavioural test (todo 59) |
| W4-11 | 95a9b4f3 | fixed, regression test names it (todo 10) |
| W4-12 | dcdb6367 | tests reworked (test-only change) (todo 59) |
| W4-13 | d2d695b7 | fixed by structure; a test names it (todo 38) |
| W4-14 | 757b48b1 | closed with H1 (D-H1): console read batches send the validated items, replies masked; no own test (todo 7) |
| W5-01 | 01e27518 | fixed, regression test names it (todo 33) |
| W5-02 | 87aef588 | fixed, regression test names it (todo 14) |
| W5-03 | 5c0dd9db | fixed, regression test names it (todo 34) |
| W5-04 | 5c0dd9db | fixed, regression test names it (todo 34) |
| W5-05 | fbab75b7 | fixed by structure; a test names it (todo 37) |
| W5-06 | 01e27518 | fixed, regression test names it (todo 33) |
| W5-07 | 79c9ab74 | copies merged into one owner; no behavioural test (todo 60) |
| W5-08 | 79c9ab74 | fixed by structure; a test names it (todo 60) |
| W5-09 | 51b16a94 | fixed by structure; no behavioural test (todo 66) |
| W5-10 | 79c9ab74 | fixed by structure; a test names it (todo 60) |
| W5-11 | d2d695b7 | fixed, regression test names it (todo 38) |
| W5-12 | 01e27518 | fixed, regression test names it (todo 33) |
| W5-13 | 187d183f | fixed by structure; a test names it (todo 23) |
| W5-14 | 79c9ab74 | fixed by structure; no behavioural test (todo 60) |
| W5-15 | 79c9ab74 | copies merged into one owner; no behavioural test (todo 60) |
| W5-16 | 5c0dd9db | fixed by structure; a test names it (todo 34) |
| W5-17 | 79c9ab74 | tests reworked; a test names it (todo 60) |
| X-01 | 66e93982 | ci.yml and container.yml trigger on master; links and CONTRIBUTING updated (workflow change) (todo 70) |
| X-02 | 66e93982 | components added and lint-completeness runs last; `rustup run stable` kept per critic, not the alt row (todo 70) |
| X-03 | 85ab24ca | e2e step() runs each step under set -e; proved with a scratch failing step (script change) (todo 73) |
| X-04 | 66e93982 | release and container workflows call the ci.yml gates before build/push (workflow change) (todo 70) |
| X-05 | 04a8b590 | fixed by structure; a test names it (todo 72) |
| X-06 | 22244caa | decision D-VET: ISRG and Zcash audit sets imported, 25 exemptions pruned (supply-chain files) (todo 71) |
| X-07 | 22244caa | xtask workspace gets its own cargo vet set and a CI vet step (supply-chain files) (todo 71) |
| X-08 | 66e93982 | all checkouts set persist-credentials: false (workflow change) (todo 70) |
| X-09 | 66e93982 | tag builds pass VERSION; :latest only for tags without '-', proved with a stub podman (workflow change) (todo 70) |
| X-10 | 85ab24ca | web-smoke.sh passes the password through a 0600 --env-file; proved with a stubbed podman (todo 73) |
| X-11 | 22244caa | kcc-rci moved to getrandom 0.4 (getrandom::fill); skip reasons in clippy.toml and deny.toml updated (todo 71) |
| X-12 | 66e93982 | ci-local.sh runs the gates in CI's order (script change) (todo 70) |
| X-13 | 66e93982 | fixed, regression test names it (todo 70) |
| N1 | e6eff40c | last_read parameter removed with its callers; the one test of only that parameter was replaced (todo 31) |
| N2 | 2a5255e7 | fixed, regression test names it (todo 30) |
| N3 | b7e853d5 | fixed, regression test names it (todo 9) |
| N4 | 0e73cdcb | fixed, regression test names it (todo 16) |
| N5 | c9722278 | fixed, regression test names it (todo 39) |
| N7 | b7e853d5 | fixed, regression test names it (todo 9) |
| N8 | 49f5f14e | fixed, regression test names it (todo 51) |
| N9 | 9ad8b7d4 | already typed by the B-08 catalog work (034ec919); this commit adds the typed test only (todo 41) |
| N11 | 95a9b4f3 | fixed, regression test names it (todo 10) |
| N12 | 95a9b4f3 | fixed, regression test names it (todo 10) |
| N16 | 5c0dd9db | fixed, regression test names it (todo 34) |
| N17 | 57489daa | fixed, regression test names it (todo 17) |
| H4a | b57d6e95 | fixed with G-01 (H4): a radio mapping rewrites every WifiMasterN/<child> word; regression test (todo 3) |
