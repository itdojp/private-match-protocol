# Protocol Governance

## Authority

ITDO Inc. maintains this repository. Public specifications are reviewable artifacts, not an independent certification of the commercial service.

## Artifact status

Every protocol artifact should use one of these statuses:

- `draft` — incomplete or under active design
- `candidate` — coherent and ready for conformance review
- `experimental` — implemented or tested in bounded experiments without compatibility commitment
- `stable` — reviewed, versioned, and subject to compatibility policy
- `deprecated` — retained for migration or evidence purposes
- `withdrawn` — unsafe, invalid, or no longer supported

Only a human maintainer may promote an artifact to `stable`.

## Versioning

Protocol messages and behavior use explicit versions.

A breaking change includes:

- changing the meaning of an existing field
- adding a required field to an existing version
- changing accepted state transitions
- weakening verification, replay, expiry, consent, or disclosure requirements
- changing canonical encoding or signature input
- changing output semantics in a way that alters disclosed information

Breaking changes require a new protocol version. Old readers should not infer new semantics from unknown fields.

## Decision records

Material decisions require an ADR containing:

- context
- options considered
- security and privacy assumptions
- evidence
- rejected alternatives
- compatibility impact
- decision owner and date
- review or expiry date where applicable

## Publication gate

Before material is merged into this public repository, reviewers must confirm:

- IP and patent review, when the content may disclose an invention
- security review, when implementation or attack details are included
- privacy review, when leakage or personal data is discussed
- claims review, when wording could be read as assurance or certification
- license review for code, test vectors, datasets, or copied definitions

Publication approval does not mean production approval.

## Security reports

Do not open public issues for suspected vulnerabilities. Use GitHub private vulnerability reporting or the security contact designated by ITDO Inc. Public disclosure occurs after remediation and approval.

## Conformance

Conformance means compatibility with a named specification and test suite version. It does not by itself establish:

- cryptographic security
- absence of side channels
- legal compliance
- deployment security
- correctness of private input data
- production readiness

## Corrections and withdrawal

When a material error is found:

1. identify affected specifications, vectors, claims, and assurance reports
2. publish a correction or withdrawal notice
3. mark affected versions and evidence
4. preserve history unless it creates an active security risk
5. define migration or re-verification requirements

## Relationship to the commercial product

The private product repository may implement additional internal controls. Public protocol claims must not imply that unpublished controls have been independently reviewed. Public assurance evidence is published through `itdojp/private-match-assurance`.
