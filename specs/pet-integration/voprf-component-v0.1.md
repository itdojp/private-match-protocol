<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# RFC 9497 / CIRCL VOPRF component profile v0.1

This experimental component profile pins Cloudflare CIRCL `v1.6.4` and RFC 9497.
It is **not** a complete PSI or Private Match decision engine.

The component does not define:

- set or intersection semantics;
- symmetric `MATCH`, `NO_MATCH`, or `INDETERMINATE` results;
- Protocol session, replay, transcript, or query-budget behavior;
- contribution, callback, cancellation, cleanup, or opaque-receipt semantics;
- application protection for low-entropy inputs.

A future complete profile must supply and review those semantics. The registry,
handoff contract, validator, and negative fixtures reject any attempt to select
this component as `selected_integration_profile` or promote its output into a
complete decision. RFC 9497 component properties do not establish application
security, input completeness, or a production architecture.

Component registration permits only local contract validation. It does not
authorize CIRCL execution. Any future component experiment requires a separate
reviewed grant, and this component can never satisfy the complete-profile
selection field by itself.
