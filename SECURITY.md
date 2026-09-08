# Security Policy

LLM Sensitive Data Firewall is intended to reduce sensitive-data exposure in LLM applications. It should not be treated as a complete compliance solution by itself.

## Security design assumptions

- Detection is probabilistic and can miss sensitive data.
- Redaction can break downstream application behavior if not configured carefully.
- Tool calls are a first-class leak surface.
- Logs and traces are a first-class leak surface.
- The model should not be trusted as the only privacy control.

## Non-goals

- Certifying HIPAA, PCI, SOC 2, or GDPR compliance by itself
- Replacing legal review
- Guaranteeing perfect sensitive-data detection
- Serving as a general-purpose endpoint protection or SIEM product

## Reporting a Vulnerability

Please report suspected vulnerabilities through the repository security advisory flow (GitHub: Security → Report a vulnerability) or by email to info@broadnet.ai with "LSDF security" in the subject. If neither is available in your fork or mirror, open a minimal public issue that asks for a private security contact without including exploit details.

Do not include real credentials, real PHI, customer data, employee data, proprietary prompts, raw audit lines, or plaintext vault contents in a report. Use synthetic examples and describe the affected LSDF version, configuration, gateway mode, detector families, and the smallest safe reproduction you can provide.

Expected response for a maintained release is acknowledgement within five business days, followed by triage, impact assessment, and coordinated remediation guidance when the report is valid.
