# Detection Documentation Standard

Each detection specification records:

- the behavior and risk being identified;
- source classification and validation status;
- required logs, event identifiers, fields, and retention assumptions;
- original SIEM queries with schema assumptions;
- safe positive and negative test procedures;
- expected results and common false positives;
- triage questions and enrichment sources;
- framework mapping with a brief rationale; and
- limitations, evasion opportunities, and environmental dependencies.

A query is labeled **specification complete** until it has been executed against an authorized lab dataset. Production validation is never inferred from a syntactically plausible query.
