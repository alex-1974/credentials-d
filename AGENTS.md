# Repository Engineering Context

This repository is part of the `d-geospatial-workspace`.

Before changing architecture, public API, credential storage semantics,
secret lifetime, cryptographic boundaries, dependencies, tests, CI, releases,
repository structure, or toolchain work, read the relevant canonical workspace
documents under `.workspace/`.

Canonical workspace documents:

- `.workspace/README.md`
- `.workspace/ROADMAP.md`
- `.workspace/DESIGN_PRINCIPLES.md`
- `.workspace/DLANG_PRACTICES.md`
- `.workspace/RESEARCH.md`
- `.workspace/QUALITY_GATES.md`
- `.workspace/GIT_GITHUB_WORKFLOW.md`
- `.workspace/REPOSITORY_STANDARD.md`
- `.workspace/TOOLCHAIN_ISSUES.md`

The workspace documents are the shared engineering contract.

`credentials-d` is a security-sensitive generic credential-storage library.
Secret lifetime, copying, persistence, deletion, platform trust boundaries,
failure behaviour, and dependency/update policy are part of the public
security contract where claimed.

Do not duplicate normative workspace rules in this repository.

When `.workspace/` is unavailable in a standalone clone, follow the tracked
repository documentation and explicitly note that workspace context was not
available.
