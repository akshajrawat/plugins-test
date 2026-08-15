# Plugin Submission PoC - Final Manual Checklist

## 1. Normal new-plugin submission

A normal new-plugin submission completed successfully: `npm run submit` passed from a clean, pushed commit with valid metadata and a successful build; the generated issue contained the expected title, repository URL, version, and commit hash; the scan identified it as a `New Plugin` and returned a clean report for that exact commit; applying `status: approved` published and verified the registry files, manifest data, README entry, release asset, and stats processing; the published metadata contains `_approved: true`, `_publish_commit`, and `_publish_hash`, and the issue closed only after verification.

Issue link: https://github.com/joplin/plugins-test/issues/40
Commit: https://github.com/joplin/plugins-test/commit/f04c977c3b6250802e96f6ad5b1b5f19b5b0f32a

## 2. Valid plugin update with version bump

A valid plugin update with a version bump completed successfully: the plugin was submitted from its registered repository with a strictly greater version; the scan identified it as an `Update` and validated the exact repository URL and commit; approval published the update; and the registry and release contain the new version without duplicate files or assets, with the issue closing after successful verification.

Issue link: https://github.com/joplin/plugins-test/issues/42

Publication commit: https://github.com/joplin/plugins-test/commit/c7632da11a2508795f503648622551e80145e263

## 3. Update without version bump

An update without a version bump was submitted using the currently published version; the scan rejected it with the `version ... is not greater` message, the issue remained open for correction, and no registry, release, or stats changes were published.

Issue link: https://github.com/joplin/plugins-test/issues/43

## 4. Ownership and migration paths

The ownership and migration rejection paths were verified: submitting an existing plugin ID from a different repository produced an ownership rejection, closed the issue, and published nothing; submitting a legacy NPM-backed plugin without a registered `repository_url` required maintainer verification and rejected publication.

Ownership-by-ID rejection issue: https://github.com/joplin/plugins-test/issues/47
Legacy NPM migration rejection issue: https://github.com/joplin/plugins-test/issues/45

## 5. Scan rejection paths

- Missing JSON: https://github.com/joplin/plugins-test/issues/50
- Malformed JSON: https://github.com/joplin/plugins-test/issues/51
- Missing required field: https://github.com/joplin/plugins-test/issues/52
- Wrong field type: https://github.com/joplin/plugins-test/issues/53
- Invalid plugin name: https://github.com/joplin/plugins-test/issues/54
- Invalid version: https://github.com/joplin/plugins-test/issues/55
- Invalid repository URL: https://github.com/joplin/plugins-test/issues/56
- Invalid commit hash: https://github.com/joplin/plugins-test/issues/57
- Incorrect issue title: https://github.com/joplin/plugins-test/issues/58
- Missing `package.json`: https://github.com/joplin/plugins-test/issues/59
- Malformed `package.json`: https://github.com/joplin/plugins-test/issues/60
- Missing `src/manifest.json`: https://github.com/joplin/plugins-test/issues/61
- Malformed `src/manifest.json`: https://github.com/joplin/plugins-test/issues/62
- Package-name mismatch: https://github.com/joplin/plugins-test/issues/63
- Missing manifest `repository_url`: https://github.com/joplin/plugins-test/issues/64
- Forbidden `_npm_package_name`: https://github.com/joplin/plugins-test/issues/65
- Payload/manifest version mismatch: https://github.com/joplin/plugins-test/issues/66
- Payload/manifest repository mismatch: https://github.com/joplin/plugins-test/issues/67

## 6. Exact commit enforcement

- [x] Exact-commit enforcement was verified: commit A received a completed clean scan, the issue payload was then changed to commit B without scanning it, and approval was rejected because no completed report matched the exact repository URL and commit hash. The issue remained open and nothing was published.

Issue: https://github.com/joplin/plugins-test/issues/68
Rejected publish workflow: https://github.com/joplin/plugins-test/actions/runs/31912272196
