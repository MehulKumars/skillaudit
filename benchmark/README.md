# Benchmark

Measures skillaudit on legitimate tools and on the malicious demo skills, so that rule changes can be judged by
before-and-after numbers instead of by impression.

> **Limit.** The malicious samples and the rules were written by the same author, so these numbers show that known
> techniques are covered. They are not a real-world detection rate. The legitimate samples are what was installed on
> one developer machine, so they over-represent browser automation, design skills and front-end packages.

## What it scans

| Side | Samples | Where they come from |
|---|---|---|
| Legitimate, named | Public packages and skills, reported by name | Folders listed in `samples.local.json` |
| Legitimate, local | Everything else on the machine (installed skills, node packages, ...) | Same file; reported only as group totals |
| Needs a human | Samples whose status is undecided | Same file; never counted as legitimate or malicious |
| Malicious | The demo skills from `tests/fixtures.py` | Built in a temporary folder and deleted afterwards |
| Size check | One legitimate package copied 1, 4 and 16 times; one demo with 0, 3 and 15 copies added | Built in a temporary folder |

Nothing scanned is ever executed. Every demo script starts with a stop line, and payload addresses are reserved
(`.invalid`, 203.0.113.0/24). Samples that are not on disk (for example a demo file that Windows Security deletes on
sight) are listed in every report, never silently skipped.

Local samples are split by a hash of their id into a tuning half and a held-back half. Held-back samples appear only as
totals and are not labelled, so they can show at the end whether changes generalise.

## Running it

```bash
cp benchmark/samples.example.json benchmark/samples.local.json   # then point it at folders on your machine
python benchmark/run.py --tag baseline-1.0.0                     # scan (parallel, cached by content)
python benchmark/run.py --tag baseline-1.0.0 --report            # rebuild reports after editing labels
python benchmark/run.py --spotcheck 20                           # draw labelled findings for a human check
```

Outputs:

- `results/<tag>.md`, `results/<tag>.json`, `results/<tag>-rules.md`: committed. Named samples in detail, local
  samples as totals, per-rule numbers from tuning samples only.
- `local/` (git-ignored): full detail including local sample names, the labelling worksheet, the spot-check list and
  the scan cache.

## Labels

CRITICAL and HIGH findings on legitimate tuning samples are labelled in `labels.json` (named samples) and
`local/labels.local.json` (local samples):

- **wrong match**: the matched text is not what the rule describes.
- **real but normal here**: true, and expected for this kind of tool.
- **needs a human**: could not be decided without more review.

A CRITICAL verdict on a legitimate sample always counts as a false alarm, whatever its labels. A rule that no malicious
sample triggers is reported as **unknown**: the benchmark cannot show whether changing it stops real detections.
Rules covered only by the pattern tests in `tests/test_rule_patterns.py` are reported as **pattern-tested**.
