# Progress

## Current state

The guard runs four layers — detection, policy, disposition and review — with a
privilege boundary between the component that reads untrusted content and the
component that acts on it, an audit bus recording which internal boundary each
value crosses, and six external benchmarks wired onto the whole thing.

**Detection.** A confidence-gated cascade per content kind. Tier 0 is
high-precision patterns (phone, resident id with checksum, email, bank card with
Luhn, credentials for code and JSON). Tier 1 sweeps for number-shaped runs tier 0
cannot read. Tier 2 is optional and adjudicating, where `PhoneDetectionAgent`
plugs in.

**Policy.** A versioned, diffable, self-testing rule file resolves
`label × confidence × purpose × destination × caller role` into one of six
actions. First match wins, the default fails closed. Three things are new:

- The **label vocabulary is open**: a policy declares its own labels, so a
  benchmark whose data is twenty-six personal-data fields is not forced through
  the five labels the shipped detectors emit and into `__default__`.
- The **confidence interval is half-open** `[min, max)`. One threshold splits the
  range into exactly two pieces, so `0.5` belongs to one side and no request
  lands in two rules at once — a whole class of order-dependence removed at the
  root rather than patched.
- A **structural lint** (`PolicyEngine.lint()`) catches what a single test vector
  cannot: unreachable rules, `allow` rules that name no destination (the
  invariant the review asked for — an unscoped allow means what it means only
  because of line numbers), and order-sensitive rule pairs, each reported with a
  concrete witness that the engine actually resolves to the earlier rule. A
  witnessed pair downgrades to `order-pinned` once an expectation covers it.
  `load_policy(..., strict=True)` refuses a policy with an error-level finding.

**Disposition.** One handler per transforming action — mask, hash, tokenise —
plus block and review. Handlers now render from `(value, label)`, so an agent
releasing a typed field it holds reuses the same transforms as the span path.

**Separation.** `QuarantinedDetectorAgent` reads the bytes and returns facts;
`PrivilegedGuardAgent` holds the authority and never opens the envelope.

**Review.** Re-checks released output both ways: the value must be gone, and
enough must be left for the task to work.

**Audit.** An `AuditBus` records every internal crossing (C1 ingress, C2
detector→policy, C3 policy→transform, C4 vault mapping, C5 agent→agent, C6
egress) by keyed digest — enough to answer "did this secret cross here", not
enough to be a place a secret goes. Per-run bus, per-bus salt.

## The six benchmarks

`python -m sensitiveguard.eval run` runs all six offline in well under a second.
Each is measured against a `no-defence` baseline; the baseline is mandatory,
because an attack-success number without one is a fact about the dataset.

| Benchmark | Edge it measures | Baseline → guarded |
|---|---|---|
| AirGapAgent-R | contextual integrity over a 26×10 field/scenario grid | privacy 70.8% → 97.1%, utility 100% |
| PrivacyLens | a helpful agent over-shares (no attacker) | leak 100% → 0%, task 100% |
| AgentDAM | web-agent minimisation + routing cost | leak 100% → 0%, cost = deterministic rule evals, 0 model calls |
| AgentLeak | which internal channel a secret crossed | C5 leak 100% → 0% |
| AgentDojo | injection through a tool result | ASR 100% → 0%, clean task still 100% |
| ASB | injection across attack families | ASR 100% → 0%, flat across families |

The guarded wins are structural, not filters: the injected instruction never
reaches the planner, the secret never crosses the agent-to-agent channel, the
over-shared field is not authorised for the recipient, and the adversarial
pretext cannot move a verdict because it never reaches the component deciding.

The bundled datasets are small, legible stand-ins that exercise the same code
paths as the upstream releases (which this environment cannot fetch). Each
benchmark's runner takes `--data <path>` and a `normalize_*` helper maps upstream
records onto the internal shape; the adapter is only `field → label` and
`scenario → destination`.

## Verification

- `./init.sh`: Ruff clean, format clean, 219 tests, compileall, all three
  policies lint clean (only pinned `info` findings), all six benchmarks run.
- Every benchmark policy passes its own expectations and the structural lint.
- Injection ASR is 100% on the no-defence baseline and 0% guarded, while the
  clean controls still complete — a defence that passed by refusing everything
  would fail the control.

## Known limits

- AirGapAgent-R accuracy shows the engine reproduces its rule set, not that the
  norms are right: the rules and the ground truth were written from the same
  reading. The `fallthrough` counter is the honest companion — a high privacy
  score with a high fallthrough would be scoring by declining everything. Here
  utility is 100% and privacy is deliberately below it, keeping a handful of real
  category-vs-cell disagreements rather than fitting them away.
- The benchmark planners are deterministic. They measure whether the
  architecture forwards attacker text to the component with authority — a
  property of the wiring. A model-backed planner drops in behind the same
  protocol and would additionally measure a model's persuasion resistance, which
  is a different, noisier question.
- Tier 1 is a dependency-free stand-in for a span model such as GLiNER.
- `Quarantine` is a boundary the pipeline enforces, not an OS-level sandbox.
