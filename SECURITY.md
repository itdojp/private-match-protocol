# Security Policy

## Reporting a suspected vulnerability

Do not open a public GitHub Issue or disclose exploit details in a pull request.

Use GitHub private vulnerability reporting when it is enabled for this
repository:

<https://github.com/itdojp/private-match-protocol/security/advisories/new>

If GitHub reports that private vulnerability reporting is unavailable, use the
[ITDO Inc. contact form](https://c.itdo.jp/contacts/) with the subject
`Private Match security report`. Include only the affected repository and
version plus safe contact information, and request a private response channel.
Do not put exploit details, customer data, secrets, keys, or tokens in the form.
Send technical details only after ITDO Inc. establishes a private response
channel.

Include, when safe:

- affected protocol, schema, reference component, or test suite version
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
