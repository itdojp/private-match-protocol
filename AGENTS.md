# AGENTS.md

## Purpose

This repository contains public protocol specifications, reference components, formal models, and conformance assets for Private Match.

## Work model

- Work from a GitHub Issue.
- Handle one issue per branch and pull request.
- Do not push directly to `main`.
- Do not merge pull requests.
- Do not create new issues unless a human explicitly requests it.
- Make the smallest coherent change that satisfies the issue.

## Public boundary

Never add:

- customer or interview data
- private service source code or infrastructure
- production endpoints, hostnames, account IDs, or keys
- commercial pricing or sales strategy
- abuse-detection thresholds
- unpublished inventions or patent candidates
- unremediated vulnerability details
- content copied from private repositories without publication approval

Stop and report when an issue requires private material.

## Protocol rules

1. State the threat model and trust assumptions before a security claim.
2. Separate protocol safety, privacy, availability, and business requirements.
3. Define public inputs, private inputs, outputs, metadata, and residual leakage.
4. Define replay, expiry, session binding, participant binding, and version behavior.
5. Define failure semantics; missing verification material must fail closed.
6. No silent fallback from production proof or protocol modes to mock or test modes.
7. Do not invent cryptographic primitives.
8. Prefer standards, reviewed papers, maintained implementations, and published test vectors.
9. Treat exact count, small intersections, and repeated adaptive queries as disclosure risks.
10. Record non-goals and unresolved assumptions explicitly.

## Formal and conformance work

- A generated formal model is a draft until reviewed.
- Tool absence, timeout, skipped checks, and parse failure are not successful verification.
- Report state-space bounds and configuration with model-checking results.
- Include positive, negative, tamper, replay, expiry, and cross-session test vectors.
- Do not claim cryptographic security from schema validation, unit tests, or state-machine model checking alone.

## Context conflicts

Inspect the issue, `README.md`, `GOVERNANCE.md`, and applicable specifications before changing files.

Report one of:

```text
Context Pack conflict: none
```

or

```text
Context Pack conflict: found
```

Do not silently resolve a material conflict in privacy, protocol meaning, compatibility, publication, or licensing.

## Pull request requirements

The PR body must include:

- linked issue
- protocol scope and version impact
- assumptions changed or added
- public/private boundary check
- security and privacy claim boundary
- validation and tools used
- skipped or unavailable checks
- compatibility impact
- known limitations
- `Context Pack conflict` result

## Human-only decisions

Require explicit human approval for:

- cryptographic protocol selection for production
- public license and patent strategy
- declaring a stable or production-ready protocol version
- weakening disclosure, replay, consent, or verification rules
- accepting a security assumption with material business impact
- publishing vulnerability details
