# Plugin Submission PoC Checklist

## Deliverable

- [ ] Provide documented proof of scanner accuracy.
- [ ] Provide a video showing the complete workflow:
  - [ ] A developer runs `npm run publish` on a fresh plugin.
  - [ ] A submission issue is created in `plugins-test`.
  - [ ] The security workflows run and check the submitted plugin.
  - [ ] A scan report is generated for reviewers.
  - [ ] A reviewer approves the plugin with the `status: approved` label.
  - [ ] The plugin's `.jpl` artifact appears in the test registry's `plugins` folder.
  - [ ] `manifests.json` is updated with the new plugin entry.

The PoC is complete when both deliverables above have been produced and every workflow step shown in the video succeeds.

## 1. Generate and submit the plugin

- [x] Generate or update a plugin with `joplin/packages/generator-joplin`.
- [x] Build the generated plugin successfully.
- [x] Run the generated plugin's publish command successfully.
- [x] Validate the plugin metadata before submission.
- [x] Create the expected issue title and JSON payload containing `plugin_name`, `version`, `repository_url`, and `commit_hash`.
- [x] Confirm the submitted commit exists on the remote repository and matches the payload.
- [x] Confirm `plugins-test` accepts the generated submission payload.
- [ ] Complete a live GitHub Device Flow and create a real submission issue.

## 2. Scan the submission

- [x] Parse and validate the issue payload and title.
- [x] Check out the exact repository and commit from the submission.
- [x] Validate `package.json` and `src/manifest.json` metadata.
- [x] Validate the plugin name, version, repository URL, ownership, and version bump.
- [x] Initialize and run the CodeQL security scan.
- [x] Post the final scan report on the submission issue.
- [x] Handle scan rejection and workflow failures through the issue comment.
- [x] Complete the scan workflow review; no further scan-workflow changes are required for the PoC.
- [ ] Run the scan workflow against a real submission issue.

## 3. Approve the submission

- [ ] Confirm a maintainer can review the scan report and submitted commit.
- [ ] Confirm adding `status: approved` starts the publish workflow.
- [ ] Confirm unauthorized or invalid approval events cannot publish a plugin.

## 4. Build and publish the approved plugin

- [ ] Review the approval-triggered build and publish workflow.
- [ ] Build the exact approved repository commit.
- [ ] Confirm the built manifest matches the approved plugin name, version, repository URL, and commit.
- [ ] Publish through `plugin-repo-cli`.
- [ ] Update the plugin registry files and generated repository metadata.
- [ ] Update the GitHub Release assets.
- [ ] Close the submission issue only after publishing succeeds.
- [ ] Confirm failures do not leave the registry, release, or issue in an incorrect final state.

## 5. Complete the PoC end to end

- [ ] Run one fresh plugin through generation, issue creation, scanning, approval, and publishing.
- [ ] Confirm the published `.jpl` matches the submitted and approved plugin.
- [ ] Confirm `manifests.json` contains the new plugin entry.
- [ ] Record the complete successful workflow.
- [ ] Document the scanner-accuracy results and supporting evidence.
