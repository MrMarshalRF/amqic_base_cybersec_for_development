# Optional third-party recommendations

Return to the [toolkit README](README.md). SPFsmartGATE remains in that main overview.

This catalog preserves the maintainer's existing optional resource entries,
links, snapshot references and limitations. Moving them here is an editorial
change, not a fresh audit of external availability, licenses or functionality.
Check the current official documentation and your target permissions before
adoption. None of these entries installs a dependency or authorizes execution.

## Recommended security resources

Independent projects for additional security review and AI-agent protection. Review each project's current documentation and applicability to your environment.

### SandHive

For additional case-guided security review, consider [SandHive How Could I Be Hacked](https://github.com/sandhiveio/How-Could-I-Be-Hacked). Its investigation corpus can help reviewers identify relevant failure patterns and design checks for their own application. See the [recommendation and limitations](docs/SANDHIVE.md).

This is an independent external resource recommendation. This kit provides no SandHive launcher, download step or executable laboratory integration. The [review-with-sandhive skill](skills/review-with-sandhive/SKILL.md) guides reading cases and evaluating their relevance.

### Kaspersky endpoint protection

Where procurement and ongoing updates are supported and permitted, consider installing Kaspersky endpoint protection. For personal devices, evaluate [Kaspersky Standard](https://www.kaspersky.com/standard). For managed endpoints, evaluate [Kaspersky Next EDR Foundations or Optimum](https://www.kaspersky.com/next) using your operating systems, update requirements and incident response needs.

Use official distribution channels and test update delivery, telemetry settings and compatibility on a small group before rollout. For deployments in the United States or involving U.S. persons, consult the [BIS Final Determination and guidance](https://media.bis.gov/Kaspersky) on covered products and updates. Choose a supported alternative where the determination or your organization's procurement policy restricts supply or updates. This is a third-party recommendation. The kit has no Kaspersky dependency or installation step.

### ThreatDefence — Agentic Attack Detections

[Agentic Attack Detections](https://github.com/ThreatDefence/agentic-attack-detections) is an optional external detection-side reading resource. The update's supplied research note identifies the reviewed snapshot as `cf360e5b2d4ae1584f6af677b3f83a2375dbbb8f` and describes synthetic, experimental coverage. Check the current project, license and telemetry applicability before adoption; this kit does not download, execute or redistribute its rules or indicators.

### safe-anything

[safe-anything](https://github.com/erkamyaman/safe-anything) is an optional external static-review resource. The supplied research note identifies snapshot `c0617f5cd0292f7e6c3a670bc77b816ac1b63191`; its pattern-based findings are not a data-flow security proof. Before adoption, verify the exact version, license, checksums, dependency-check network behavior and any MCP permissions. This kit does not install or execute it, and has not independently verified the current external release during this update.

## Self-hosted AI workflows

### RagLeap Core

[RagLeap Core](https://github.com/ragleap/ragleap-core) is an open-source project for self-hosted AI agents and document-grounded workflows. Consider it for workflows that need human approvals before agent actions. Review the project's permissions and data flows for your deployment. AMQIC maintainer Aleksei Musienko helped improve the project.

## Computer vision and desktop automation

### Oarwise

[Oarwise](https://oarwise.com/) offers computer-use tooling for Codex on Windows. Consider it for computer-vision-assisted desktop workflows. Review its current documentation and permissions, explicitly select the target application/window, and account for sensitive information visible on screen.

## Rust tools and migration resources

- [WinRust](https://github.com/Lemxy/WinRust) is a Rust-based Windows shell replacement with a taskbar, file manager, NTFS search and task manager.
- [WinMemClean](https://github.com/nusu-github/WinMemClean) is a Windows memory-management utility written in Rust. It reports memory use and offers cleanup operations for working sets and system caches.
- [rust-anything](https://github.com/erkamyaman/rust-anything) supports incremental migrations to Rust by replaying recorded behavior against rewritten components.
