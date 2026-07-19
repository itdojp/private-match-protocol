# ADR-0001: Public repository licensing

- Status: Accepted
- Decision owner: ITDO Inc.
- Decision date: 2026-07-19
- Human approval: Explicitly approved by human direction for the PR #7 review response
- Review date: 2026-10-18

## Context

This public repository contains both narrative protocol documentation and executable or
machine-consumable reference artifacts. A public license and patent strategy is a human-only
decision under `AGENTS.md`. The human direction for PR #7 explicitly approved the license
allocation recorded here.

This decision applies only to material approved for publication in
`itdojp/private-match-protocol`. It does not authorize publication of material from private
product or strategy repositories.

## Decision

- Narrative protocol documentation, research text, tables, and diagrams use CC BY 4.0.
- Executable and reference code, Python and TypeScript code, JSON Schemas, validators, tests,
  fixtures, conformance vectors, GitHub Actions, machine-readable reference contracts, and
  build inputs use Apache License 2.0.
- `REUSE.toml` is the machine-readable SPDX file mapping. Full license texts are stored in
  `LICENSES/`.
- Patent-sensitive or trade-secret candidate material remains private or embargoed until a
  separate human IP and publication approval is recorded.

## Options considered

1. Retain the previous no-additional-license position.
2. Apply Apache-2.0 to every file.
3. Apply CC-BY-4.0 to every file.
4. Use the approved dual-license mapping based on artifact type.

Option 4 was selected because it gives executable/reference artifacts a software license while
using a documentation license for narrative material.

## Security and privacy assumptions

- A public license does not establish protocol security, privacy, conformance, certification,
  production readiness, or legal compliance.
- Repository publication review continues to exclude credentials, customer information,
  private infrastructure, unpublished inventions, patent candidates, trade secrets, and
  unremediated vulnerability details.
- The Apache-2.0 patent provisions do not replace the separate human patent/publication gate.

## Evidence

- The explicit human license decision supplied for the PR #7 review response.
- `REUSE.toml` and the full texts in `LICENSES/`.
- `reuse lint` in the pull-request validation workflow.

## Rejected alternatives

- Option 1 was rejected because public reference artifacts require an explicit license before
  publication.
- Options 2 and 3 were rejected because one license does not express the approved distinction
  between software/reference artifacts and narrative documentation.

## Compatibility impact

This changes the repository from no additional public license to the approved explicit mapping.
It does not change protocol messages, output semantics, disclosure policy, or artifact status.
Later file categories must receive an explicit SPDX mapping before publication.
