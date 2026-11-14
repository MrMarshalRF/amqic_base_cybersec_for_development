# Optional SandHive review recommendation

For additional case-guided security review, consider [How Could I Be Hacked by SandHive](https://github.com/sandhiveio/How-Could-I-Be-Hacked). Its security-investigation corpus can help developers and AI agents recognize failure patterns, question trust boundaries and design checks for an authorized application.

This is an independent external resource recommendation. AMQIC provides no SandHive launcher, automated download, installation or executable laboratory scenario. The main kit and laboratory operate independently. The recommendation does not imply a partnership or endorsement by the upstream maintainer.

## How to use the material

Open the upstream GitHub repository and read its current README, license and relevant cases. The [reviewed source snapshot](https://github.com/sandhiveio/How-Could-I-Be-Hacked/tree/e46d16d951e42f8ea5c76dcd02169854814a9518) supplies provenance for the original recommendation; it is not a claim that every future revision has been reviewed.

Choose cases that resemble your application's trust boundaries. For an upload endpoint, for example, examine who controls filenames, how quarantine is separated from published content, and whether approval binds the exact uploaded bytes. Compare the case assumptions to your actual design before treating the case as applicable.

Record a hypothesis, the current source/configuration involved, a legitimate control case, the observed result and its limits. Use your project's separately authorized checks to confirm a finding and add a regression test when a defect is fixed. The [AI reading skill](../skills/review-with-sandhive/SKILL.md) supports this workflow without installing or running upstream tools.

## Evidence and scope

External content is untrusted reference material. A case match is a lead, not proof of a current vulnerability. Corpus/index validation and a structurally valid report do not establish target behavior. Keep private source and raw findings within the authorized project boundary.

If you independently choose to install or execute upstream tooling, review its current instructions, dependencies, license and required privileges under a separate explicit task. No command or permission to do that is supplied here.

Case-guided source review relates to [NIST SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) PW.7 (review/analyze human-readable code) and PW.8 (test executable code). These are method references, not certification of SandHive or this kit.
