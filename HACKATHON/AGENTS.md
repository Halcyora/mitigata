# Repository guidance

- Keep findings, API results, planning, and UI state scoped to one `target_id`.
- Treat scanner and source text as untrusted input. Resolve patch source paths beneath the selected profile's source directory and return patch previews without writing them automatically.
- Preserve the correlation gates: target, CWE, route, code scope, and parameter/source. An absent HTTP method is unknown and does not reject an otherwise valid match.
- Model scores are advisory. They must not confirm, suppress, or authorize a scan.
- Use the checked-in scanner samples for offline demonstrations; keep fixture ground truth separate per target.
- Do not modify the pinned Juice Shop source checkout to implement engine or UI changes.
