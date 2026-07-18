# Actors and Trust Boundaries

## Status

- Artifact status: draft
- Protocol profile: `private-match-core/v0.1`
- Scope: two-party, decision-only protocol before PET profile selection

This document defines responsibilities and prohibited data flows. It does not establish cryptographic security.

## Party clients

Each party controls a local client that imports and normalizes its private input. The initial core profile requires raw identifiers and normalized private inputs to remain inside the originating client boundary.

The protocol does not assume that a participant submits a truthful, complete, current, or authorized dataset. A participant can omit records or construct a probing subset. Dataset authenticity and completeness require a separate issuer, source-system attestation, organizational approval, contract, or review process.

A client is trusted only to protect its own local data before protocol preparation. A compromised client defeats protection for that party's endpoint.

## Coordinator

The coordinator is authoritative for:

- session and participant binding
- policy version
- nonce, sequence, replay, and idempotency state
- query budget
- terminal status
- approved audit events

It is not permitted to receive raw identifiers, normalized private inputs, matching elements, or reveal payloads under the core profile.

The target profile also prohibits the coordinator from learning the decision outcome. This is a requirement, not an established property; implementation and PET-profile evidence are required.

The coordinator necessarily observes operational metadata, including participant routing identifiers, policy and session identifiers, message times, counts, size classes, completion status, and error category.

## Service operator

An authorized operator may access aggregate operational status and approved audit fields. Operational access must not imply access to private inputs, matching elements, or the decision outcome. Administrative interfaces are a separate security boundary from protocol endpoints.

## Assurance pipeline

The private assurance pipeline receives digests, normalized statuses, tool metadata, and public-safe configuration. Public exports must not contain raw evidence, private inputs, customer identifiers, secrets, topology, or unresolved exploit details.

## Network observer

Transport encryption is required, but network observers may still learn endpoints, timing, message frequency, duration, and byte counts. The core contract does not claim traffic-analysis resistance.

## Malicious participant

A participant may:

- choose, omit, or fabricate its inputs
- replay, reorder, duplicate, or tamper with messages
- start additional sessions within external authorization limits
- adapt later inputs based on earlier results
- create a boolean membership oracle through carefully chosen inputs
- collude with a compromised coordinator, endpoint, or identity unless the selected PET profile explicitly covers that case

The protocol therefore requires authoritative query budgets, one accepted result per commitment pair, session binding, minimum-set policy, and abuse monitoring. These controls reduce risk but do not eliminate inference across multiple identities or legitimate organizations.

## Trust not yet selected

The project has not selected a production PSI, OPRF/VOPRF, MPC, TEE, or ZKP integration profile. Consequently, the following remain unresolved:

- semi-honest versus malicious security
- coordinator/party collusion protection
- contribution unlinkability
- set-size hiding or padding
- outcome confidentiality mechanism
- trusted hardware and attestation requirements
- key and setup assumptions

Each PET integration profile must publish its own security model and residual leakage without overriding the core minimum-disclosure rules.
