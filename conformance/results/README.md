<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Conformance results

This directory documents the result boundary; generated run results are not committed here.
The reference verifier writes deterministic JSON only to an explicitly supplied repository-local
output directory. An execution timestamp, hostname, environment variable, or publication approval
belongs to a separate private Evidence producer and is not part of the Protocol run result.

All six statuses (`pass`, `fail`, `skip`, `unsupported`, `timeout`, and `tool-error`) remain distinct.
A negative Protocol case that is rejected as expected has runner status `pass`; this does not mean
that the message was accepted.
