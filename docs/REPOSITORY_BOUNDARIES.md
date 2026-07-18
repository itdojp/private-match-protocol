# Repository Boundaries

## Overview

Private Match uses separate repositories because publication status, access control, license, and release cadence differ.

| Repository | Visibility | Authority | Contains | Must not contain |
|---|---|---|---|---|
| `private-match-protocol` | public | protocol maintainers | specifications, schemas, reference components, conformance, formal models | production service, customer information, commercial strategy |
| `private-match-research` | public | research maintainers | market, use-case, technology, and substitute research | customer-identifying discovery, pricing strategy, unpublished inventions |
| `private-match-product` | private | product engineering | commercial implementation, infrastructure, internal controls | public source of truth for protocol claims |
| `private-match-strategy` | private | company leadership | ownership, hypotheses, customer discovery, pricing, IP, legal and publication decisions | production secrets and routine implementation code |
| `private-match-assurance` | public | assurance maintainers | sanitized release evidence, claims, assumptions, manifests, known limitations | raw private logs, source code, customer data, exploit details |

## Direction of authority

- Research may motivate requirements but does not directly change protocol semantics.
- Protocol specifications define the public contract implemented by the product.
- Product implementation produces private evidence.
- Assurance publishes reviewed, sanitized evidence about named protocol and product releases.
- Strategy decides publication, product priority, IP handling, and go/no-go outcomes.

## Handoffs

### Research to protocol

A research handoff contains:

- validated decision problem
- required minimum output
- unacceptable disclosures
- buyer and workflow assumptions
- technology evidence and open risks
- disconfirming findings

It must not contain customer-identifying information.

### Protocol to product

A protocol handoff contains:

- versioned schemas
- state machine
- public/private input definitions
- conformance vectors
- assumptions and leakage contract
- compatibility policy

The product must not silently reinterpret these artifacts.

### Product to assurance

A product evidence export contains:

- artifact and source revision digests
- protocol and conformance suite versions
- tool versions and runner identity
- pass, fail, skip, and timeout status
- sanitized test and formal summaries
- assumptions and known limitations

The export must not contain raw datasets, private source, secrets, internal topology, or unresolved exploit details.

## Conflict handling

When repositories disagree:

- public protocol meaning is resolved in `private-match-protocol`
- public evidence meaning is resolved in `private-match-assurance`
- product implementation is changed to match the approved protocol or a new protocol version is proposed
- commercial priority and publication decisions are resolved in `private-match-strategy`

No repository should silently override another repository's authority.
