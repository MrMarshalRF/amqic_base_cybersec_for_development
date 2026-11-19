# Vulnerability disclosure and testing scope

This policy supplements [SECURITY.md](../SECURITY.md). Report privately to [cyber@amqic.ai](mailto:cyber@amqic.ai). Use the acknowledgement, assessment and progress targets published there.

## Scope and authorization

This public repository welcomes source review and non-disruptive testing of your own isolated copy using synthetic data. No public test service is provided. Publishing the repository, a contact address or security.txt does not authorize testing amqic.ai, maintainer accounts, production infrastructure, other users or any third-party system. A separate live engagement requires the operator's explicit asset scope, permitted methods, schedule, rate/concurrency caps and stop contacts before it begins.

Stay within that scope. Do not perform denial of service, password spraying, social engineering, credential use, persistence or access to another person's data. Stop if a test unexpectedly reaches real data or a system outside the agreed scope, and contact the responsible operator privately. An identifying header can assist correlation but grants no exemption from authentication, limits or data boundaries.

## What to include

- Affected repository file and exact commit/release, or an explicitly authorized asset.
- Expected and observed behavior, prerequisites and a minimal safe reproduction using synthetic data.
- The observed security impact and evidence supporting it; distinguish confirmed behavior from a hypothesis.
- Relevant request/response excerpts or test results, with credentials and personal/customer data removed.
- Any automation or AI assistance relevant to reproducibility. Personally check the technical claims; generated prose or scanner output is not proof.

Do not obtain additional unauthorized access to demonstrate severity. A credible partial report can still merit investigation. Keep sensitive details out of public issues while the report is assessed. Send only the minimum evidence needed; arrange a safe private exchange if necessary.

## Assessment

We assess reproducibility, impact and affected integrations. Writing style, language fluency or suspected AI authorship is not a reason to dismiss a report. Missing evidence may require clarification; duplicates can be linked to an existing private case. Configuration advice, theoretical risks and an exploitable defect are different findings, and each is assessed in context.

Reporter code and attachments are untrusted. Maintainers should inspect them before any execution and reproduce accepted cases in an isolated environment without secrets. Do not run a submitted command on production or automatically dispatch report contents to a privileged agent.

This policy does not create a paid bounty or promise a reward. Coordinate disclosure through the private contact after assessment and remediation. Operators adopting the kit must publish their own asset-specific policy; this repository's policy does not speak for their systems.
