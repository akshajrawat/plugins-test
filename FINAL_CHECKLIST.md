# Plugin Submission PoC - Final Manual Checklist

Record the issue, scan, publish, registry, release, and terminal URLs for each completed checklist.

## 1. Normal new-plugin submission

- [ ] **New plugin end-to-end:**
  - `npm run submit` passes with a clean, pushed commit, valid metadata, and a successful build.
  - The issue has the expected title and contains the exact repository URL, version, and commit hash.
  - The scan identifies `New Plugin` and produces a completed clean report for that exact commit.
  - Adding `status: approved` starts publication; the registry folder, `manifests.json`, `README.md`, release asset, and `stats.json` are updated.
  - Published metadata contains `_approved: true`, `_publish_commit`, and `_publish_hash`; the issue closes only after verification.

Evidence: Issue _ | Scan _ | Publish _ | Registry _ | Release _

## 2. Valid plugin update with version bump

- [ ] **Existing plugin update:**
  - Submit from the registered repository with a strictly greater version.
  - Confirm the scan identifies `Update` and validates the exact repository URL and commit.
  - Approve and publish the update successfully.
  - Confirm the registry and release now contain the new version, with no duplicate files or assets, and the issue closes.
  - Repeat with URL variants (`.git`, trailing slash, case, or `www`) to verify normalization.

Evidence: Issue _ | Scan _ | Publish _ | Registry _ | Release _

## 3. Update without version bump

- [ ] **Same-version update:**
  - Submit an existing plugin using the currently published version.
  - Confirm the scan rejects it with the `version ... is not greater` message.
  - Confirm the issue remains open for correction and nothing changes in the registry, release, or stats.
  - Repeat with a lower version and relevant prerelease/build variants; confirm each is rejected as not greater.

Evidence: Issue _ | Scan _

## 4. Ownership and migration paths

- [ ] **Ownership checks:**
  - Submit an existing plugin ID/name from a different repository; confirm ownership rejection, issue closure, and no publication.
  - Submit a legacy NPM-backed plugin with no registered `repository_url`; confirm maintainer verification is required and publication is rejected.
  - Verify lookup works when the existing entry is found by manifest ID and when found by plugin name.

Evidence: Issue(s) _ | Workflow(s) _

## 5. Local and scan rejection paths

- [ ] **Preflight and payload rejection:** Confirm dirty-tree, unpushed-commit, invalid-metadata, and build failures make `npm run submit` exit non-zero without creating an issue.
- [ ] **Issue validation rejection:** Test missing/malformed JSON, missing or wrongly typed fields, invalid name/version/repository/commit, and an incorrect issue title; each reports a clear rejection and publishes nothing.
- [ ] **Repository validation rejection:** Test missing or malformed `package.json`/`src/manifest.json`, package-name mismatch, missing `repository_url`, forbidden `_npm_package_name`, and payload/manifest version or repository mismatch.
- [ ] **Scan failure:** Test a missing/failed/malformed SARIF result and a known malicious plugin; confirm findings or `Security Scan Failed`, linked logs, an open issue, and no publication.
- [ ] **Exact commit enforcement:** Scan commit A, then approve a submission for commit B; confirm publish rejects it because no completed report matches the exact URL and hash.

Evidence: Terminal _ | Issue(s) _ | Workflow(s) _

## 6. Approval, publish failure, and retry paths

- [ ] **Approval without a valid scan:** Approve an issue with no completed matching scan or a failed scan; confirm `Plugin Publish Rejected`, no mutation, and an open issue.
- [ ] **Non-submission label:** Apply labels to an issue without the `[Plugin Submission]` title; confirm the publish workflow does not process it.
- [ ] **Build/artifact failure:** Fail dependency installation, build, or artifact-count validation; confirm a failure comment, an open issue, and no publication.
- [ ] **Publish CLI failure:** Make `publish-plugin` reject the artifact; confirm the CLI reason is reported and no partial publication is accepted.
- [ ] **Verification failure:** Use an artifact with mismatched identity, version, repository, commit, or hash; confirm registry verification fails and the issue stays open.
- [ ] **Release/registry failure:** Fail release/stat updates or the registry push; confirm the issue does not receive a false success/closed state.
- [ ] **Retry/recovery:** Correct the failure and retry; confirm publication completes exactly once, without duplicate registry files or release assets, and closes the issue only after verification.

Evidence: Issue _ | Failed workflow _ | Retry _ | Registry _ | Release _

## 7. Rule-regression gate

- [ ] **Regression workflow:** Safe plugins complete with zero findings and pass; malicious fixtures appear in the combined summary and fail; missing, failed, or malformed results report `CodeQL regression scan incomplete` and fail.

Evidence: Passing workflow _ | Findings workflow _ | Incomplete workflow _
