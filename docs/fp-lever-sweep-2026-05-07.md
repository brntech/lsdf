# Broad-pii-ml score_threshold sweep

_Generated 2026-05-07T05:14:52Z._

Profile: `broad-pii-ml`. Threat dataset: `evals/piece_b_replay.json` (40 cases). Benign datasets: `evals/false_positive.json` (4), `evals/utility_matrix.json` (65).

Sweep varies `OpenAIPrivacyFilterDetector.score_threshold` while keeping every other detector and rule unchanged. Goal: lowest threshold whose **threat sensitive_values_leaked_after stays at 0** (no recall regression) while **benign findings drop ≥50%** vs the baseline (0.50).

| score_threshold | threat after-leak (cases / values) | benign findings (regex / entropy / medical-regex / privacy-filter / total) |
| ---: | --- | --- |
| 0.50 | 0 / 0 | 0 / 0 / 2 / 28 / 31 |
| 0.70 | 0 / 0 | 0 / 0 / 2 / 27 / 30 |
| 0.85 | 0 / 0 | 0 / 0 / 2 / 0 / 3 |
| 0.95 | 0 / 0 | 0 / 0 / 2 / 0 / 3 |

## Per-corpus benign breakdown

| score_threshold | corpus | passed / cases | findings by family |
| ---: | --- | --- | --- |
| 0.50 | false_positive.json | 0 / 4 | openai_privacy_filter=4 |
| 0.50 | utility_matrix | 47 / 65 | gliner=1, medical-regex=2, openai_privacy_filter=24 |
| 0.70 | false_positive.json | 0 / 4 | openai_privacy_filter=4 |
| 0.70 | utility_matrix | 47 / 65 | gliner=1, medical-regex=2, openai_privacy_filter=23 |
| 0.85 | false_positive.json | 4 / 4 | _none_ |
| 0.85 | utility_matrix | 65 / 65 | gliner=1, medical-regex=2 |
| 0.95 | false_positive.json | 4 / 4 | _none_ |
| 0.95 | utility_matrix | 65 / 65 | gliner=1, medical-regex=2 |

## Reproduce

```bash
docker compose --profile optional run --rm optional-cli fp-lever-table --threshold 0.50 --threshold 0.70 --threshold 0.85 --threshold 0.95 --format markdown 2>/dev/null
```
