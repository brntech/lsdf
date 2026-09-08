# LSDF System Recall

_Generated 2026-05-07T16:38:29Z. Commit 25adb2d31209._

Foundation-layer detector recall and specificity against synthetic fixtures, independent of profile composition.

Optional adapter rows use deterministic, capability-aware test providers in this foundation harness; they exercise entity mapping and shape recognition without downloading model weights.

Coverage gaps: 17 profile/entity pairs in gated profiles have no in-scope detector with a non-zero foundation floor.
Floor met? compares current metrics to the declared manifest floor; out-of-scope rows are engines that do not target the entity by design.

## Summary - active-profile detectors

| Detector | Entity | Corpus | Recall | Specificity | Floor met? | TP | FN | FP | TN |
| --- | --- | --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| contextual-broad.generic_identity | ADDRESS | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual-broad.generic_identity | BLOOD_TYPE | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| contextual-broad.generic_identity | DATE_OF_BIRTH | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual-broad.generic_identity | EMAIL | foundation | 0.000 | 1.000 | N/A - engine does not target | 0 | 30 | 0 | 15 |
| contextual-broad.generic_identity | OTHER_PHI | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual-broad.generic_identity | PERSON | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual-broad.generic_identity | PHONE | foundation | 0.000 | 1.000 | N/A - engine does not target | 0 | 30 | 0 | 15 |
| contextual-broad.output_shapes | ADDRESS | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual-broad.output_shapes | DATE_OF_BIRTH | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| contextual-broad.output_shapes | OTHER_STRONG_ID | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| contextual-broad.output_shapes | PERSON | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual-broad.output_shapes | PHONE | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| contextual.identity_document | CUSTOMER_ID | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | DRIVER_LICENSE | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | EMPLOYEE_ID | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | LICENSE_PLATE | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | NATIONAL_ID | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | OTHER_INTERNAL_ID | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | OTHER_STRONG_ID | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | PASSPORT | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | STUDENT_ID | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | USER_ID | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.secret_field | API_KEY | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.secret_field | BEARER_TOKEN | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.secret_field | OTHER_SECRET | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.secret_field | PASSWORD | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.xml_identity | DRIVER_LICENSE | foundation | 0.000 | 1.000 | N/A - engine does not target | 0 | 30 | 0 | 15 |
| contextual.xml_identity | EMAIL | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.xml_identity | PASSPORT | foundation | 0.000 | 1.000 | N/A - engine does not target | 0 | 30 | 0 | 15 |
| contextual.xml_identity | PHONE | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| entropy.secret | OTHER_SECRET | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| gliner.pii_phi | ADDRESS | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| gliner.pii_phi | BANK_ACCOUNT | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | BLOOD_TYPE | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | CREDIT_CARD | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | CUSTOMER_ID | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | DATE_OF_BIRTH | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | DRIVER_LICENSE | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | EMAIL | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| gliner.pii_phi | EMPLOYEE_ID | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | HEALTH_INSURANCE_ID | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| gliner.pii_phi | IBAN | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | LICENSE_PLATE | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | MEDICAL_CONDITION | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | MEDICATION | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | MRN | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | NATIONAL_ID | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | OTHER_INTERNAL_ID | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | PASSPORT | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | PERSON | foundation | 1.000 | 0.933 | yes | 30 | 0 | 1 | 14 |
| gliner.pii_phi | PHONE | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | STUDENT_ID | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | TAX_ID | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | USER_ID | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | US_SSN | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| medical-regex.phi_pattern | DIAGNOSIS_TEXT | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| medical-regex.phi_pattern | ICD_CODE | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| medical-regex.phi_pattern | LAB_VALUE | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| medical-regex.phi_pattern | MEDICAL_CONDITION | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| medical-regex.phi_pattern | MEDICATION | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| medical-regex.phi_pattern | OTHER_PHI | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| openai_privacy_filter.reference_model | ADDRESS | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| openai_privacy_filter.reference_model | BANK_ACCOUNT | foundation | 0.967 | 0.933 | yes | 29 | 1 | 1 | 14 |
| openai_privacy_filter.reference_model | DATE_OF_BIRTH | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| openai_privacy_filter.reference_model | EMAIL | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| openai_privacy_filter.reference_model | OTHER_SECRET | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| openai_privacy_filter.reference_model | PERSON | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| openai_privacy_filter.reference_model | PHONE | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| regex.api_key_family | API_KEY | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.aws_key | AWS_KEY | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.azure_key | AZURE_KEY | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.bearer_token | BEARER_TOKEN | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.contact_identity_family | ADDRESS | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.contact_identity_family | DATE_OF_BIRTH | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.contact_identity_family | EMAIL | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.contact_identity_family | PERSON | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.contact_identity_family | PHONE | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.database_url | DATABASE_URL | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.datadog_key | DATADOG_KEY | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.financial_family | BANK_ACCOUNT | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.financial_family | CREDIT_CARD | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.financial_family | IBAN | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.jwt | JWT | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.medical_identifier_family | MRN | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.pem_private_key | PEM_BLOCK | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.private_key | PRIVATE_KEY | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.secret_assignment | API_KEY | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.secret_assignment | BEARER_TOKEN | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.secret_assignment | OTHER_SECRET | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.secret_assignment | PASSWORD | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.secret_assignment | PRIVATE_KEY | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.strong_identifier_family | BR_CPF | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.strong_identifier_family | NATIONAL_ID | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.strong_identifier_family | OTHER_STRONG_ID | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.strong_identifier_family | TAX_ID | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.strong_identifier_family | US_SSN | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |

## Full matrix

| Detector | Entity | Corpus | Recall | Specificity | Floor met? | TP | FN | FP | TN |
| --- | --- | --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| contextual-broad.generic_identity | ADDRESS | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual-broad.generic_identity | BLOOD_TYPE | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| contextual-broad.generic_identity | DATE_OF_BIRTH | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual-broad.generic_identity | EMAIL | foundation | 0.000 | 1.000 | N/A - engine does not target | 0 | 30 | 0 | 15 |
| contextual-broad.generic_identity | OTHER_PHI | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual-broad.generic_identity | PERSON | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual-broad.generic_identity | PHONE | foundation | 0.000 | 1.000 | N/A - engine does not target | 0 | 30 | 0 | 15 |
| contextual-broad.output_shapes | ADDRESS | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual-broad.output_shapes | DATE_OF_BIRTH | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| contextual-broad.output_shapes | OTHER_STRONG_ID | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| contextual-broad.output_shapes | PERSON | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual-broad.output_shapes | PHONE | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| contextual.identity_document | CUSTOMER_ID | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | DRIVER_LICENSE | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | EMPLOYEE_ID | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | LICENSE_PLATE | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | NATIONAL_ID | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | OTHER_INTERNAL_ID | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | OTHER_STRONG_ID | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | PASSPORT | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | STUDENT_ID | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.identity_document | USER_ID | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.secret_field | API_KEY | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.secret_field | BEARER_TOKEN | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.secret_field | OTHER_SECRET | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.secret_field | PASSWORD | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.xml_identity | DRIVER_LICENSE | foundation | 0.000 | 1.000 | N/A - engine does not target | 0 | 30 | 0 | 15 |
| contextual.xml_identity | EMAIL | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| contextual.xml_identity | PASSPORT | foundation | 0.000 | 1.000 | N/A - engine does not target | 0 | 30 | 0 | 15 |
| contextual.xml_identity | PHONE | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| entropy.secret | OTHER_SECRET | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| gliner.pii_phi | ADDRESS | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| gliner.pii_phi | BANK_ACCOUNT | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | BLOOD_TYPE | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | CREDIT_CARD | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | CUSTOMER_ID | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | DATE_OF_BIRTH | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | DRIVER_LICENSE | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | EMAIL | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| gliner.pii_phi | EMPLOYEE_ID | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | HEALTH_INSURANCE_ID | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| gliner.pii_phi | IBAN | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | LICENSE_PLATE | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | MEDICAL_CONDITION | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | MEDICATION | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | MRN | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | NATIONAL_ID | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | OTHER_INTERNAL_ID | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | PASSPORT | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | PERSON | foundation | 1.000 | 0.933 | yes | 30 | 0 | 1 | 14 |
| gliner.pii_phi | PHONE | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | STUDENT_ID | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | TAX_ID | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | USER_ID | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| gliner.pii_phi | US_SSN | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| medical-regex.phi_pattern | DIAGNOSIS_TEXT | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| medical-regex.phi_pattern | ICD_CODE | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| medical-regex.phi_pattern | LAB_VALUE | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| medical-regex.phi_pattern | MEDICAL_CONDITION | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| medical-regex.phi_pattern | MEDICATION | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| medical-regex.phi_pattern | OTHER_PHI | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| openai_privacy_filter.reference_model | ADDRESS | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| openai_privacy_filter.reference_model | BANK_ACCOUNT | foundation | 0.967 | 0.933 | yes | 29 | 1 | 1 | 14 |
| openai_privacy_filter.reference_model | DATE_OF_BIRTH | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| openai_privacy_filter.reference_model | EMAIL | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| openai_privacy_filter.reference_model | OTHER_SECRET | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| openai_privacy_filter.reference_model | PERSON | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| openai_privacy_filter.reference_model | PHONE | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| presidio.analyzer | ADDRESS | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| presidio.analyzer | BANK_ACCOUNT | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| presidio.analyzer | CREDIT_CARD | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| presidio.analyzer | EMAIL | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| presidio.analyzer | IBAN | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| presidio.analyzer | OTHER_PHI | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| presidio.analyzer | PERSON | foundation | 1.000 | 1.000 | yes | 30 | 0 | 0 | 15 |
| presidio.analyzer | PHONE | foundation | 0.967 | 0.933 | yes | 29 | 1 | 1 | 14 |
| presidio.analyzer | US_SSN | foundation | 0.967 | 1.000 | yes | 29 | 1 | 0 | 15 |
| regex.api_key_family | API_KEY | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.aws_key | AWS_KEY | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.azure_key | AZURE_KEY | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.bearer_token | BEARER_TOKEN | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.contact_identity_family | ADDRESS | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.contact_identity_family | DATE_OF_BIRTH | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.contact_identity_family | EMAIL | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.contact_identity_family | PERSON | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.contact_identity_family | PHONE | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.database_url | DATABASE_URL | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.datadog_key | DATADOG_KEY | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.financial_family | BANK_ACCOUNT | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.financial_family | CREDIT_CARD | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.financial_family | IBAN | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.jwt | JWT | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.medical_identifier_family | MRN | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.pem_private_key | PEM_BLOCK | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.private_key | PRIVATE_KEY | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.secret_assignment | API_KEY | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.secret_assignment | BEARER_TOKEN | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.secret_assignment | OTHER_SECRET | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.secret_assignment | PASSWORD | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.secret_assignment | PRIVATE_KEY | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.strong_identifier_family | BR_CPF | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.strong_identifier_family | NATIONAL_ID | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.strong_identifier_family | OTHER_STRONG_ID | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.strong_identifier_family | TAX_ID | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| regex.strong_identifier_family | US_SSN | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |
| xpia.indirect_injection | PROMPT_INJECTION | foundation | 1.000 | 1.000 | yes | 4 | 0 | 0 | 3 |

## Gaps - gated profile entities without an in-scope foundation floor

| Entity | Reached via profile(s) | Enabled detector(s) |
| --- | --- | --- |
| BLOOD_TYPE | healthcare | _none_ |
| CUSTOMER_CONFIDENTIAL | broad-pii, broad-pii-ml, healthcare | _none_ |
| EMPLOYEE_COMPENSATION | broad-pii, broad-pii-ml, healthcare | _none_ |
| HEALTH_INSURANCE_ID | healthcare | _none_ |
| OAUTH_TOKEN | broad-pii, broad-pii-ml, healthcare | _none_ |
| SWIFT | broad-pii, broad-pii-ml, healthcare | _none_ |
| WEBHOOK_URL | broad-pii, broad-pii-ml, healthcare | _none_ |
