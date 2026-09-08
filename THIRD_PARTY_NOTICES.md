# Third-Party Notices

LSDF-authored source, including every detector adapter, is licensed under [Apache-2.0](LICENSE). Third-party datasets, Python packages, and model weights retain their own licenses and notices. The four default bundled threat corpora are `piece_b_replay`, `medical_phi_replay`, `nemotron_pii`, and `br_agentic_pii`; the third-party-derived fixtures are attributed below.

## NVIDIA Nemotron-PII

- Bundled artifact: `evals/nemotron_pii.json` (100-case sample).
- Publisher and dataset owner: NVIDIA Corporation.
- Authors credited by the dataset card: Amy Steier, Andre Manoel, Alexa Haushalter, and Maarten Van Segbroeck.
- Source and citation: [NVIDIA Nemotron-PII dataset card](https://huggingface.co/datasets/nvidia/Nemotron-PII).
- Upstream license: [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/legalcode), as stated by the dataset card (checked 2026-09-08).
- LSDF adaptations: domain-stratified sampling, wrapping source text as OpenAI-compatible response fixtures, mapping source labels to LSDF entities, and adding containment expectations and unmapped-label metadata. The builder is `scripts/build_nemotron_pii_corpus.py`.

The upstream dataset is described as synthetic. Attribution identifies its source; it does not imply NVIDIA endorses LSDF or its reported results.

## Operator-Supplied ai4privacy Benchmark (Not Bundled)

The earlier sample derived from [ai4privacy/pii-masking-300k](https://huggingface.co/datasets/ai4privacy/pii-masking-300k) is no longer distributed. Its recorded aggregate measurements in LSDF documentation are historical external benchmark evidence. The earlier corpus metadata recorded CC-BY-NC-4.0 for the OpenPII-220k subset; consult the upstream dataset terms for the exact version and use you select rather than treating that historical field as current permission.

Operators must obtain the appropriate dataset permissions before supplying a local LSDF-format benchmark. Keep the data and local results under ignored `.lsdf/external-benchmarks/`, outside Git and release artifacts. See [Measured Protection](docs/measured-protection.md#operator-supplied-external-benchmark) for the four-plus-external evaluation command and healthcare's unchanged missing-corpus gate.

## Optional Detector Packages and Weights

GLiNER, Presidio, and OpenAI privacy-filter integrations are explicitly optional; the default LSDF runtime does not require them. LSDF's adapter code is included under Apache-2.0. Installing upstream packages or downloading weights does not put those artifacts under LSDF's license.

| Component | Upstream project or exact reference model |
| --- | --- |
| GLiNER package | [GLiNER upstream](https://github.com/urchade/GLiNER) |
| GLiNER reference weights | [E3-JSI/gliner-multi-pii-domains-v1 model card](https://huggingface.co/E3-JSI/gliner-multi-pii-domains-v1) |
| Presidio package | [Microsoft Presidio upstream](https://github.com/microsoft/presidio) |
| spaCy package and optional image language model | [spaCy upstream](https://github.com/explosion/spaCy) and [en_core_web_lg 3.8.0 release](https://github.com/explosion/spacy-models/releases/tag/en_core_web_lg-3.8.0) |
| OpenAI privacy-filter reference weights | [openai/privacy-filter model card](https://huggingface.co/openai/privacy-filter) |
| Transformers package | [Transformers upstream](https://github.com/huggingface/transformers) |
| PyTorch package | [PyTorch upstream](https://github.com/pytorch/pytorch) |

The optional image includes the spaCy `en_core_web_lg` 3.8.0 language model. GLiNER and OpenAI privacy-filter weights require separate model-cache preparation. Review the licenses and notices for the exact package versions and model revisions installed, including any replacement model selected by an operator. Model weights and their training datasets are separate artifacts with their own terms.

## guardion/BR-Agentic-PII-Benchmark

- Bundled artifact: `evals/br_agentic_pii.json`
- Source: https://huggingface.co/datasets/guardion/BR-Agentic-PII-Benchmark
- Upstream publisher: `guardion`
- License: MIT
- Upstream notes: the dataset card describes the corpus as synthetic Brazilian Portuguese banking-agent conversations and states that no real personal data is included.

No separate copyright notice was published in the upstream dataset repository when this notice was added. The attribution above preserves the available upstream notice for the redistributed evaluation sample.

MIT License

Copyright notice: not provided by upstream dataset repository.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this dataset and associated documentation files (the "Dataset"), to deal
in the Dataset without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Dataset, and to permit persons to whom the Dataset is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Dataset.

THE DATASET IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE DATASET OR THE USE OR OTHER DEALINGS IN THE
DATASET.
