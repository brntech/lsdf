# LSDF Detector Comparison

- Dataset: utility_matrix
- Profile: default
- Mode: enforce
- Cases: 65

| Set | Status | Families | Passed | Failed | Blocked | After-Leak Cases | After-Leak Values | Audit Violations |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| presidio | unavailable | presidio | 0 | 0 | 0 | 0 | 0 | 0 |
| privacy | unavailable | openai_privacy_filter | 0 | 0 | 0 | 0 | 0 | 0 |
| default_optional | unavailable | regex, entropy, medical, presidio, openai_privacy_filter | 0 | 0 | 0 | 0 | 0 | 0 |

## Unavailable Sets

- `presidio`: Install presidio-analyzer to enable detector family 'presidio'
- `privacy`: Install transformers and a supported model cache to enable detector family 'openai_privacy_filter'
- `default_optional`: Install presidio-analyzer to enable detector family 'presidio'

## Failing Sets

No failing detector sets.
