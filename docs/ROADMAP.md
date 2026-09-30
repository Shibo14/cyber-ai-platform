# Roadmap

## Status

This roadmap records confirmed sequencing decisions and clearly labeled planning placeholders. Production readiness requires a separate validation and explicit release gate; gate criteria, dates, owners, and the feature-by-feature MVP order remain **TBD**. The README vision list is not itself a committed delivery schedule.

## Confirmed scope boundaries

Outside MVP:

- Advanced anti-VM evasion.
- Autonomous destructive response.
- Local inference or a local production sandbox.
- Full air-gapped deployment.

## Confirmed technology-stage transition

| Stage | Confirmed decision | Remaining detail |
|---|---|---|
| MVP | Redis Streams for asynchronous work | Queue topology, delivery/retry semantics, capacity and release gate: TBD |
| Production | Kafka for asynchronous work | Migration/cutover, operating model, compatibility and timing: TBD |

## Candidate planning structure (not approved milestones)

The following headings are placeholders to organize future planning, not an approved sequence or commitment. Completing the MVP does **not** mean the platform is production-ready. Production readiness must be established separately through production validation and an explicit release gate; the validation scope and gate criteria are **TBD**.

1. **MVP definition and security design** — select user-facing workflow, supported samples, acceptance criteria, and operational details. Scope and exit criteria: TBD.
2. **MVP delivery** — implement and verify the approved capability set using confirmed Architecture v2 decisions, including Redis Streams. Included features and release date: TBD.
3. **Production readiness** — candidate work may include defining and executing the Redis Streams-to-Kafka transition and validating RTO/RPO objectives. Production readiness requires separate validation and an explicit release gate; scope, criteria, and dates: TBD.
4. **Post-MVP capabilities** — consider the broader README vision and explicitly excluded capabilities through separate decisions. Priority and timing: TBD.

## Open roadmap decisions

- MVP workflow and feature boundary.
- Milestones, owners, dependencies, dates, and acceptance gates.
- Production cutover criteria for Kafka.
- Which vision capabilities follow MVP and whether excluded capabilities are reconsidered.
