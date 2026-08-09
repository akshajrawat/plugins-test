# Plugin Submission PoC - Final Manual Checklist

- [ ] **New plugin success:** Generate and implement a plugin, commit and push it, run `npm run submit`, confirm the issue payload and exact commit are scanned, review the completed report, add `status: approved`, confirm publication succeeds, verify the registry and GitHub Release, and confirm the issue closes.
  - Issue URL: _
  - Scan workflow URL: _
  - Publish workflow URL: _
  - Registry commit URL: _

- [ ] **Update without a version bump:** Submit an existing plugin without changing its published version and confirm the scan rejects it with a clear message and nothing is published.
  - Issue URL: _
  - Workflow URL: _

- [ ] **Valid plugin update:** Bump the version, commit and push it, submit it, confirm the scan identifies an update, approve it, and verify the new registry and release version.
  - Issue URL: _
  - Scan workflow URL: _
  - Publish workflow URL: _

- [ ] **Local submission rejection:** Confirm `npm run submit` rejects uncommitted changes, an unpushed commit, invalid metadata, and a failed build; each attempt must exit with an error without creating an issue.
  - Terminal evidence: _

- [ ] **Scan rejection and failure:** Confirm invalid issue metadata or an ownership conflict is rejected, known malicious test code produces the expected findings, and a failed CodeQL/SARIF run reports `Security Scan Failed`, links the logs, leaves the issue open, and publishes nothing.
  - Issue URL(s): _
  - Workflow URL(s): _

- [ ] **Publish rejection, failure, and retry:** Confirm approval without a completed scan publishes nothing, a build or artifact failure posts a failure comment and leaves the issue open, and retrying completes without duplicate registry files or release assets.
  - Issue URL: _
  - Failed workflow URL: _
  - Retry workflow URL: _

- [ ] **Rule regression workflow:** Confirm all configured safe plugins produce a complete zero-finding pass, any finding appears in the combined summary and fails the workflow, and a missing, failed, or malformed result reports `CodeQL regression scan incomplete` and fails.
  - Passing workflow URL: _
  - Findings workflow URL: _
  - Incomplete workflow URL: _
