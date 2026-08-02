# Plugin Submission PoC Review Checklist

This checklist reflects the end-to-end review of `generator-joplin`, the `plugins-test` workflows, and `plugin-repo-cli`. It also incorporates validation performed with the generated plugin in `C:\opensource\test`.

## Maintainer review progress

- [x] Review scan workflow initialization and metadata validation.
- [x] Review Phase 1: identity and initial validation.
- [x] Review Phase 2: environment provisioning and target-repository validation.
- [ ] Review Phase 3: CodeQL database initialization.
- [ ] Review Phase 4: CodeQL/SAST analysis.
- [ ] Review Phase 5: final report generation and scan failure handling.
- [ ] Review the approval-triggered build and publish workflow.

## Verified in the generated test plugin

- [x] Publish-flow source files match the current generator branch behavior.
- [x] TypeScript compilation succeeds in the generated project.
- [x] `npm run publish` starts successfully.
- [x] Metadata validation succeeds.
- [x] `npm run dist` succeeds from the publish flow.
- [x] Exactly one `.jpl` and one JSON manifest are produced.
- [x] The generated manifest ID, version, and `repository_url` are correct.
- [x] `_publish_commit` contains the branch and exact 40-character Git commit SHA.
- [x] `_publish_hash` matches the SHA-256 of the generated `.jpl`.
- [x] The local commit matches the remote GitHub branch.
- [x] Mocked submission targets `joplin/plugins-test/issues` with the expected title and JSON body.
- [x] `plugins-test` accepts the generated submission payload.
- [ ] Complete GitHub Device Flow in a controlled live test.
- [ ] Create a real submission issue in a controlled live test.
- [ ] Run the scan and publish workflows end to end in GitHub.

## 1. Secure the scan-completion gate

- [ ] Do not accept an arbitrary issue comment as evidence of a completed scan.
- [ ] Verify the scan comment author or GitHub App identity.
- [ ] Bind the report to a trusted workflow run, check run, artifact, attestation, or bot-managed label.
- [ ] Verify the trusted result matches the exact repository URL and commit SHA being approved.
- [ ] Add coverage proving a submitter-authored forged report is rejected.

## 2. Define and enforce the scan scope

- [x] Review `.github/codeql/codeql-config.yml`, which limits analysis to `src`.
- [x] Confirm that the PoC intentionally scans plugin code under `src/` only.
- [x] Keep the current PoC scan scope aligned with CodeQL by treating `src/` as the plugin-code scan boundary.
- [ ] Decide how dependency code and lifecycle/install scripts are handled.
- [ ] Document any intentionally excluded code or dependencies.
- [ ] Ensure validation and documentation describe the same scan scope.

## 3. Revalidate versions during final publish

- [ ] Add the "new version must exceed the existing version" check to the trusted `plugin-repo-cli publish-plugin` operation.
- [x] Keep the scan-time version check for early reviewer feedback.
- [ ] Test two approved submissions published out of order.
- [ ] Test attempts to republish the same version.
- [ ] Test attempts to downgrade an existing plugin.

## 4. Complete and repair regression validation

- [ ] Add the missing twentieth plugin to `.github/codeql/target-plugins.json`; it currently contains 19.
- [ ] Give every matrix result artifact a unique filename or directory.
- [ ] Do not merge identically named `findings.json` files in a way that overwrites results.
- [ ] Make aggregation fail when any matrix scan fails or does not upload a result.
- [ ] Run `codeql test run` in CI for the CodeQL rule test directories.
- [ ] Ensure changes under `.github/codeql/tests/**` trigger the appropriate workflow.
- [ ] Add or document the planned 5-10 malicious-plugin validation set.
- [ ] Preserve evidence of the zero-false-positive and malicious-plugin results.

## 5. Align submission contracts and types

- [x] Add `version` to `SubmissionPayload`.
- [x] Validate that the payload version matches the checked-out manifest version.
- [x] Validate that the issue-title version matches the manifest version.
- [x] Use strict runtime validation for every payload field instead of truthiness checks.
- [x] Validate that the final built artifact version matches the approved issue payload.
- [x] Reject unexpected types with a clear issue comment rather than a workflow exception.
- [ ] Replace GitHub client, context, and action-core `any` types where practical.
- [ ] Add `_approved?: boolean` to the shared `PluginManifest` type if it is a permanent registry field.
- [ ] Parse `_approved` in `manifestFromObject` if clients or the frontend will consume it.
- [ ] Define whether `_approved` means human-reviewed, security-reviewed, or safe, and document the semantics.
- [ ] Remove or use the currently unused `validateRegistryOwnership` helper in `plugins-test`.

## Completed scan-validation cleanup

- [x] Merge metadata validation into `initialize` so the issue payload is parsed once during scan initialization.
- [x] Preserve distinct parse-failure and title-rejection issue messages after merging initialization.
- [x] Require submissions to use `src/manifest.json` from the generator-joplin structure.
- [x] Parse the target repository's `package.json` exactly once and reuse it for ownership rejection.
- [x] Parse the target repository's `src/manifest.json` exactly once and reuse it for all manifest checks.
- [x] Remove the unused source-file existence gate.
- [x] Remove the unused `source_file_count` output and return property while preserving `handled_failure`.

## 6. Use the official publishing CLI safely

- [ ] Replace `@akshajrawatt/plugin-repo-cli@1.0.5` with the merged official `@joplin/plugin-repo-cli` release.
- [ ] Confirm the published official version includes the `publish-plugin` command.
- [ ] Confirm it includes repository-origin versus legacy-NPM ownership protection.
- [ ] Avoid `latest` dependency resolution in the write-capable job.
- [ ] Use a lockfile-backed, reproducible installation.
- [ ] Consider building or bundling the trusted CLI before the write-capable publish job.
- [ ] Pin security-sensitive GitHub Actions to reviewed commit SHAs.

## 7. Make plugin builds reproducible

- [ ] Replace `npm install --no-audit --no-fund` with `npm ci --no-audit --no-fund` for submitted plugins.
- [ ] Require a valid lockfile, or document and test the fallback behavior.
- [ ] Test dependency-lock mismatch failure.
- [ ] Decide whether dependency install scripts are allowed.
- [ ] Ensure any code executed during installation/build is covered by the threat model.

## 8. Test release publishing and recovery

- [ ] Document or automatically create the required initial GitHub Release.
- [ ] Validate HTTP response statuses in `updateRelease`.
- [ ] Test release lookup and upload failures.
- [ ] Test a `git push` failure after release mutation.
- [ ] Test rerunning a partially successful publication.
- [ ] Consider `workflow_dispatch` with a validated issue-number input.
- [ ] Define how to reconcile release state when registry commit/push fails.
- [ ] Test duplicate approval-label events.
- [ ] Confirm the issue closes only after all registry and release operations succeed.

## 9. Check generator update compatibility

- [ ] Run `npm run update` under every officially supported Node.js version.
- [ ] Test Node.js 20, 22, and 24, or declare an explicit supported range.
- [ ] Confirm the published generator contains the same submission flow as the current PR branch.
- [ ] Add an integration test that generates or updates a temporary plugin and runs TypeScript compilation plus `npm run dist`.
- [ ] Investigate the observed Yeoman CLI hang under Node.js 24 before the Joplin generator is invoked.

## 10. Perform a controlled live end-to-end run

- [ ] Run `npm run publish` and complete GitHub Device Flow.
- [ ] Verify token caching and invalid-token reauthentication.
- [ ] Confirm exactly one issue is created with the expected structured payload.
- [ ] Confirm the scan checks out the exact submitted commit.
- [ ] Confirm a genuine, trusted report is posted.
- [ ] Confirm the reviewer can trace every finding to the submitted commit.
- [ ] Apply `status: approved` using an authorized maintainer account.
- [ ] Confirm the build job has no registry write capability.
- [ ] Confirm artifact manifest, commit, repository URL, and hash integrity.
- [ ] Confirm `plugins/<id>/manifest.json` and `plugins/<id>/plugin.jpl` are updated.
- [ ] Confirm `manifests.json`, `README.md`, `stats.json`, and GitHub Release assets are updated.
- [ ] Repeat the test for a valid plugin update.
- [ ] Repeat the test for an ownership mismatch.
- [ ] Repeat the test for an older queued version attempting to publish after a newer version.

## Documentation follow-up

- [ ] Update the generated `GENERATOR_DOC.md` to describe the issue-based submission flow.
- [ ] Update `plugin-repo-cli` documentation for `publish-plugin`.
- [ ] Ensure the PoC documentation matches the actual use of `npm ci` or `npm install`.
- [ ] Document required labels, release prerequisites, permissions, reruns, rollback, and legacy-plugin migration.
- [ ] Clearly separate PoC-only behavior from the intended production migration.
