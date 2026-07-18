# Security Policy

## Reporting a suspected vulnerability

Do not open a public GitHub Issue or disclose exploit details in a pull request.

Use GitHub private vulnerability reporting for this repository when available. If it is unavailable, contact ITDO Inc. through an established private company channel and identify the affected repository and version.

Include, when safe:

- affected protocol, schema, reference component, or test-suite version
- impact and attacker prerequisites
- reproduction steps or test vector
- whether active exploitation is suspected
- suggested mitigation, if known
- safe contact information

Do not include real customer data, production secrets, private keys, access tokens, or unrelated internal information.

## Scope

Reports may concern:

- protocol replay, substitution, session binding, consent, or disclosure failures
- privacy or metadata leakage beyond the published contract
- canonical encoding, hashing, signature, or verification ambiguity
- unsafe test vectors or reference implementation behavior
- dependency, build, or release integrity
- public documentation that materially overstates a security property

Commercial service vulnerabilities may require coordinated handling with the private product repository and must not be copied into public Issues.

## Disclosure

ITDO Inc. will assess scope, remediation, affected versions, evidence, and disclosure timing. Public disclosure may be delayed or redacted to reduce exploitation risk. A correction, deprecation, or withdrawal may be published after review.

## Security claim boundary

Repository conformance, tests, formal models, and assurance reports do not guarantee absence of vulnerabilities. Reports should identify the exact affected subject and version.
