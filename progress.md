# Progress

## Current state

The guard runs four layers: detection, policy, disposition and review, with a
privilege boundary between the component that reads untrusted content and the
component that acts on it.

**Detection.** A confidence-gated cascade per content kind. Tier 0 is
high-precision patterns (phone, resident id with checksum, email, bank card with
Luhn, and credentials for code and JSON). Tier 1 sweeps for number-shaped runs
that tier 0 cannot read — obfuscated separators, full-width digits — and emits
them as low-confidence candidates. Tier 2 is optional and adjudicating: it
receives only those candidates, normalised, one short slice at a time, and is
where `PhoneDetectionAgent` plugs in.

**Policy.** `policy/default_policy.yaml` resolves
`label x confidence x purpose x destination x caller role` into one of six
actions. First match wins, the default is `review`, and every verdict carries the
path that produced it. The file ships ten expectations that `self_test()` runs.

**Disposition.** One handler per transforming action — mask (one-way), hash
(one-way but joinable, salted), tokenise (reversible through a vault) — plus
block and review, which withhold rather than rewrite. Restoring a response is a
policy switch, not a transformer's habit.

**Separation.** `QuarantinedDetectorAgent` reads the bytes and returns facts.
`PrivilegedGuardAgent` holds the authority and never opens the envelope.

**Review.** Re-checks released output both ways: the value must be gone
(verbatim and reformatted), and enough must be left for the task to work.

## Verification

- `./init.sh`: Ruff clean, format clean, 169 tests passed, compileall passed.
- The default policy's own expectations pass, and no rule is shadowed.
- Injection suite: six payloads that ask to be exempted, rerouted or skipped
  produce verdicts identical to benign text.
- Cost: the common path spends zero model calls; only unsettled spans escalate.

## Known limits

- Tier 1 is a dependency-free stand-in for a span model such as GLiNER. It
  trades precision for recall and leans on tier 2 or on the policy's
  low-confidence rules to clean up after it.
- The reviewer's over-redaction thresholds are heuristics, and are meant to be
  tuned per deployment against real traffic.
- `Quarantine` is a boundary the pipeline enforces, not an OS-level sandbox. It
  hardens the accidental leak — rendering a handle into a prompt or a log — and
  keeps the privileged path free of content by construction.
