# Policy Model

## Policy dimensions

Rules match entities or entity categories, surfaces, and optional minimum confidence. Rules also carry an action, severity metadata, priority, span/surface scope, and optional `on_fail` behavior. Tenant, environment, destination, and user role are not implemented rule matchers; select the appropriate policy in the application or gateway configuration.

## Actions

The executable YAML actions are listed below. Unmatched findings use the engine's allow fallback. Observation uses monitor mode or per-rule `on_fail: observe`; `allow`, `warn`, and `log` are not rule action names.

- `redact`
- `mask`
- `tokenize`
- `block`
- `replace` — replace the matched span with operator-supplied literal text. Requires `replacement: <string>` on the rule. Policy load rejects rules that supply `replacement` without `action: replace`, or `action: replace` without `replacement`.
- `hash` — replace the matched span with `<{ENTITY}:HASH:<algo>=<hex16>>` (deterministic, so audit events and traces correlate without revealing the raw value). The hex digest is truncated to 16 characters (64 bits) by design — this trades collision-resistance for in-line readability and is not operator-configurable in this version. Birthday-collision space at 64 bits is ~2^32, which is well above the cardinality of typical sensitive values LSDF sees in practice (passwords, account numbers, names). Operators who need full-length digests can wrap LSDF and post-process the audit event, where the full algorithm is recorded in the decision metadata. Optional `hash_algo: sha256 | sha512 | blake2b` on the rule, default `sha256`.
- `encrypt` — replace the matched span with `<{ENTITY}:ENC:<fernet-token>>` (reversible Fernet symmetric encryption). Requires `encrypt_key_env: <env var name>` on the rule; the env var must hold a urlsafe-base64 32-byte Fernet key. The transform raises `ValueError` at request time if the env var is unset or malformed — this is a deliberate fail-closed posture: missing key configuration must not silently degrade to a weaker action.

Manual approval and `require_approval` are not executable policy actions.

## Per-rule `on_fail`

Each rule may carry an optional `on_fail` field that overrides the policy-level `mode` for that rule alone. Valid values:

- `mask` — apply the rule's `action` transform. Default; explicit form.
- `observe` — log the decision; do not apply the transform; do not block.
- `block` — set `blocked=true` regardless of the rule's `action`; the rule's action transform also runs so the halted payload remains raw-value-safe for downstream consumers.
- `reask` — apply the transform and surface a `reask_hint` flag in the audit event for an external orchestration layer to act on.
- `exception` — raise `lsdf.PolicyEnforcementError` from `Firewall.inspect` so the gateway returns an error response.

Omitting `on_fail` honours the policy-level `mode` (enforce applies transforms; monitor logs only). See `policy-cookbook.md` § "Per-Rule `on_fail` Overrides" for recipe shapes.

## Policy file format

Policies use YAML. See the [Policy Cookbook](policy-cookbook.md) for profile choices, rule examples, and validation commands.

## Built-In Profiles

See the [Policy Cookbook profile inventory](policy-cookbook.md#profile-inventory) for the maintained list of profiles and domain packs, their detector requirements, and evaluation promises.
