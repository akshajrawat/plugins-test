# Per-plugin approved findings

Each `<plugin-id>.json` file is a reviewer-approved baseline for one plugin. The
security scan still runs every CodeQL rule globally. After scanning, findings
whose fingerprints occur exactly once in both the current scan and this
plugin's baseline are shown under **Approved Earlier**; every other finding is
shown under **Findings Requiring Review**.

Applying the `status: approved` label replaces the plugin's baseline with all
findings from the immutable scan artifact for that exact issue, repository,
commit, and workflow run. An empty approved scan removes the old plugin
baseline. Baselines are never shared between plugins.

Fingerprints include the rule ID, repository-relative file, named code
container, complete enclosing statement, same-file declarations referenced by
that statement, and in-repository CodeQL flow anchors when present. Line and
column values are stored only as reviewer hints.
