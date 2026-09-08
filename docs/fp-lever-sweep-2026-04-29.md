# Privacy-ml score_threshold sweep

_Generated 2026-04-30T00:53:57Z._

Profile: `broad-pii-ml`. Threat dataset: `evals/piece_b_replay.json` (40 cases). Benign datasets: `evals/false_positive.json` (4), `evals/utility_matrix.json` (65).

Sweep varies `OpenAIPrivacyFilterDetector.score_threshold` while keeping every other detector and rule unchanged. Goal: lowest threshold whose **threat sensitive_values_leaked_after stays at 0** (no recall regression on this corpus) while **benign findings drop ≥50%** vs the baseline (0.50).

**Recall caveat:** the threat corpus's PII cases (email / phone / SSN at fixture values) are all also caught by the regex layer. This sweep proves "no recall loss on credential shapes" but **not** "no recall loss for sub-0.85 PHONE/PERSON spans the privacy-filter would catch alone." These credential-corpus results alone do not establish recall on ML-only PII shapes.

**ML-only PII result (2026-04-30):** ran the same sweep against `evals/piece_b_replay_ml_pii.json` (6 cases the regex layer cannot catch — UK/FR/IN phone shapes, three multi-cultural given names: `Wei Chen`, `Ali Hassan`, `Fatima Okonkwo`). All four thresholds (0.50/0.70/0.85/0.95) keep `sensitive_values_leaked_after = 0`. Each case fires at the privacy-filter's confidence ceiling (≈1.00), so the 0.85 default has ~15 points of headroom on these specific shapes. This is *not* exhaustive — a noisier or more ambiguous PII shape could still land in the 0.70–0.84 band. Operators with traffic mixes that exercise harder ML-only PII should still validate their own corpus before relying on 0.85.

| score_threshold | threat after-leak (cases / values) | benign findings (regex / entropy / medical-regex / privacy-filter / total) |
| ---: | --- | --- |
| 0.50 | 0 / 0 | 0 / 2 / 1 / 31 / 34 |
| 0.70 | 0 / 0 | 0 / 2 / 1 / 30 / 33 |
| 0.85 | 0 / 0 | 0 / 2 / 1 / 3 / 6 |
| 0.95 | 0 / 0 | 0 / 2 / 1 / 3 / 6 |

## Per-corpus benign breakdown

| score_threshold | corpus | passed / cases | findings by family |
| ---: | --- | --- | --- |
| 0.50 | false_positive.json | 0 / 4 | entropy=2, openai_privacy_filter=4 |
| 0.50 | utility_matrix | 45 / 65 | medical-regex=1, openai_privacy_filter=27 |
| 0.70 | false_positive.json | 0 / 4 | entropy=2, openai_privacy_filter=4 |
| 0.70 | utility_matrix | 45 / 65 | medical-regex=1, openai_privacy_filter=26 |
| 0.85 | false_positive.json | 3 / 4 | entropy=2 |
| 0.85 | utility_matrix | 63 / 65 | medical-regex=1, openai_privacy_filter=3 |
| 0.95 | false_positive.json | 3 / 4 | entropy=2 |
| 0.95 | utility_matrix | 63 / 65 | medical-regex=1, openai_privacy_filter=3 |

## Reproduce

```bash
# Default credential-corpus sweep
docker compose --profile optional run --rm optional-cli fp-lever-table --threshold 0.50 --threshold 0.70 --threshold 0.85 --threshold 0.95 --format markdown 2>/dev/null

# ML-only PII follow-up sweep (no regex backstop)
docker compose --profile optional run --rm optional-cli fp-lever-table --threat-dataset evals/piece_b_replay_ml_pii.json --threshold 0.50 --threshold 0.70 --threshold 0.85 --threshold 0.95 --format markdown 2>/dev/null
```
