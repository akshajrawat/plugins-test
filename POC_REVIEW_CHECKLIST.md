# Plugin Submission PoC - Final Manual Checklist

Use this document only to record final manual verification. Add the issue and workflow URLs for every GitHub-based scenario.

## 1. Fresh plugin - complete success flow

- [ ] Generate a new plugin with `generator-joplin` and implement a basic working feature.
- [ ] Commit and push the plugin repository.
- [ ] Run `npm run submit`; confirm authentication succeeds and a correctly formatted submission issue is created.
- [ ] Confirm the scan checks the submitted repository and exact commit.
- [ ] Confirm the scan comment finishes with a complete findings report.
- [ ] Add `status: approved` after reviewing the report.
- [ ] Confirm the plugin builds and publishes successfully.
- [ ] Confirm the issue is closed only after publication succeeds.
- Issue URL: _
- Scan workflow URL: _
- Publish workflow URL: _

## 2. Existing plugin - forgotten version bump

- [ ] Submit an update without changing the published version.
- [ ] Confirm the scan rejects it with a clear version-bump message.
- [ ] Confirm no publish workflow changes the registry or GitHub Release.
- Issue URL: _
- Workflow URL: _

## 3. Existing plugin - valid version update

- [ ] Bump the version, commit, push, and run `npm run submit` again.
- [ ] Confirm the scan identifies it as an update and completes normally.
- [ ] Approve it and confirm the new version is published.
- [ ] Confirm the previous plugin ID remains owned by the same repository.
- Issue URL: _
- Scan workflow URL: _
- Publish workflow URL: _

## 4. Local submission validation

- [ ] Run `npm run submit` with uncommitted changes; confirm it fails locally and creates no issue.
- [ ] Run it with a commit that has not been pushed; confirm it fails locally and creates no issue.
- [ ] Try an invalid plugin name, version, or repository URL; confirm it fails with a useful message.
- [ ] Confirm every failure logs the reason and exits with a non-zero status.
- Terminal evidence: _

## 5. Invalid or inconsistent issue metadata

- [ ] Open a submission with an invalid JSON payload or missing required field.
- [ ] Test a mismatch between the issue title, payload, `package.json`, or `src/manifest.json`.
- [ ] Test an invalid repository URL or commit hash.
- [ ] Confirm each submission is rejected with a clear issue comment and is not scanned or published as successful.
- Issue URL(s): _
- Workflow URL(s): _

## 6. Plugin ownership conflict

- [ ] Submit an existing plugin ID from a different repository.
- [ ] Confirm the ownership check rejects it and nothing is published.
- Issue URL: _
- Workflow URL: _

## 7. Security findings

- [ ] Submit a test plugin that intentionally triggers one or more custom CodeQL rules.
- [ ] Confirm every expected finding appears in the issue report with its rule, file, and line.
- [ ] Confirm the reviewer can leave the submission unapproved.
- Issue URL: _
- Workflow URL: _

## 8. Scan system failure

- [ ] Cause or use a run with failed CodeQL analysis, missing SARIF, or malformed/incomplete SARIF.
- [ ] Confirm the comment says `Security Scan Failed` and explains what happened.
- [ ] Confirm it links to the workflow logs and never says `No vulnerabilities detected` or scan complete.
- [ ] Confirm the issue remains open for investigation or retry.
- Issue URL: _
- Workflow URL: _

## 9. Approval without a completed scan

- [ ] Add `status: approved` to a submission without a genuine completed scan report.
- [ ] Confirm publish initialization rejects it and no build, registry update, or release update occurs.
- Issue URL: _
- Workflow URL: _

## 10. Build or artifact failure after approval

- [ ] Approve a submission whose build fails or whose generated artifacts are missing/invalid.
- [ ] Confirm publication stops and a failure comment is posted.
- [ ] Confirm the issue remains open and the registry and release are unchanged.
- Issue URL: _
- Workflow URL: _

## 11. Retry a failed publish

- [ ] Rerun a failed workflow from GitHub Actions, or remove and reapply `status: approved`.
- [ ] Confirm the retry completes without duplicate registry entries or release assets.
- [ ] Confirm the final success comment is posted and the issue closes.
- Issue URL: _
- Original workflow URL: _
- Retry workflow URL: _

## 12. Published output verification

- [ ] Confirm `plugins/<plugin-id>/plugin.jpl` contains the approved artifact.
- [ ] Confirm `plugins/<plugin-id>/manifest.json` contains the approved version and `_approved: true`.
- [ ] Confirm `manifests.json` contains the same plugin ID and version.
- [ ] Confirm `README.md` contains the expected plugin entry.
- [ ] Confirm the versioned `.jpl` exists in the GitHub Release.
- [ ] Confirm the stored `_publish_hash` matches the published `.jpl` bytes.
- Registry commit URL: _
- GitHub Release URL: _

## Final deliverable

- [ ] All applicable scenarios above have passed and contain evidence URLs.
- [ ] Safe-plugin regression results and malicious-plugin detection results are documented.
- [ ] Record the final video: generate plugin -> `npm run submit` -> issue -> scan report -> approval -> publish -> registry/release update -> issue closed.
- [ ] **PoC final review complete.**
