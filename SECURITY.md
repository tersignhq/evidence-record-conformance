# Security

Report a vulnerability privately through GitHub's private vulnerability reporting: the
**Security** tab, then **Report a vulnerability**
(https://github.com/tersignhq/evidence-record-conformance/security/advisories/new). Do not open a
public issue or pull request for it.

## Scope

- The verifiers and engines in this repository: `verify.py`, the runners under `crypto/` and the
  tools under `tools/`.
- The evidence-bundle verifier published at https://tersign.ai/verify/v1/.

A report is in scope when one of these accepts a forged, altered or incomplete record that the
suite's rules reject, or fails on attacker-controlled input other than by rejecting it (a crash, a
hang, unbounded memory). A vector whose expected verdict or reason is wrong, or a reading that no
vector pins, is a conformance question: open an issue for it.

There is no bug bounty, and no response time is promised.
