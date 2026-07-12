# Joplin Plugin Security Pipeline - Project Plan

## 1. Project Objectives & Deliverables

The objective is to transition the Joplin plugin submission from a "trust-by-default" NPM system to a "review-by-default" github issue based submission system.
To minimize risk, this will be delivered as a fully functional Proof of Concept (PoC) working on a test repository.

### Key Requirements :

1. **Zero False-Positive on top 20 official plugins:** The pipeline must scan the Top 20 most popular plugins without generating false-positive.
2. **Threat Detection Verification:** The pipeline should successfully analyze 5-10 purpose-built malicious plugins.
3. User should be able to run `npm run publish` to open an issue on the joplin test plugin repository for the scan.
4. The scan on issue submission should work and generate a report in the issue comment for the reviewer to review.
5. When reviewer confirms the plugin is safe he should be able to start the second workflow by labeling the issue. This workflow will upsert the plugin data in the test registry and the github releases.

---

## 2. Technical Specification

### 2.1 Proposed Architecture & DX

The current Joplin plugin publishing pipeline relies on a "trust-by-default" architecture. When a developer publishes an update to the public NPM registry, an automated bot blindly pulls that package into the central Joplin ecosystem.

While this creates a frictionless Developer Experience (DX), it completely lacks automated security scanning, human reviews, and traceability back to the original source code. If a malicious or compromised package hits NPM, it is immediately distributed to Joplin users without any checking.

**The Objective:** Transition the Joplin plugin registry to a GitHub Actions-based submission queue. To minimize risk, the immediate deliverable for this project is a fully functional Proof of Concept (PoC) that operates in parallel to the existing system using a test repository, ensuring the architecture can be evaluated safely before affecting the live ecosystem.

### 2.2 Security Scanning & Tooling Selection

Testing was conducted across Semgrep, CodeQL and LLM assisted scanning here :

[Scanning Tools Testing](https://discourse.joplinapp.org/t/plugin-security-tool-comparison-codeql-semgrep-gemini-cli/50049/18)

Semgrep was found to be not too effective in current threat model use case.

CodeQl and LLM both were on equal terms with CodeQl with a trade-off that we need to write a lot and lot of custom rules for each and every flow that we can figure out during the testing phase.

CodeQl has been choosen as the Tool we will be using for our scanning pipeline right now.

---

## 3. Project Schedule :

### Milestone 1: CLI & Authentication Transition (1 PR LEFT)

- **Tasks:**
  - Make sure that the code user is submitting is not broken and has a valid public repository on github.
  - Implement GitHub Device Flow in `generator-joplin` for developer authentication.
  - Generate GitHub Issues for new plugin submissions with a structured json.

- **Deliverable:** Developers can run `npm run publish` to authenticate and securely open a submission issue on the test repository.

### Milestone 2: SAST Scanning using CodeQl and Repository update (UPDATE WORKFLOW LEFT)

- **Tasks:**
  - Integrate the CodeQl scanner with custom rules using our threat model.
  - Run the tests on top 20 joplin plugin to minimize false positives.
  - Build the workflow YAML so that every new open issue with [Plugin Submission] in the title runs through an automated scanning workflow and generates a scanning report as a comment.
  - When the accepted label is added to the issue it runs through another workflow to update the repository with the accepted plugin data.
  - Implement the **Split-Job Architecture**:
    1. _Build Job:_ Builds the untrusted code.
    2. _Publish Job:_ Uploads `.jpl` to GitHub Releases and the `/plugin` folder in the repository.
  - Create an action that fetches all the top 20 plugins and run the rules against them. There should be no error or warning
  - Setup the GitHub Actions so that the workflow runs every time a rule is changed or added.
- **Deliverable:** Automated, structured security reports posted directly to submission issues comments, after review is done add `status: approved` label to get the plugin into the repository.

### Milestone 3: Joplin Plugin Cli update (1 PR LEFT)

- **Tasks:**
  - Implement "First-Come, First-Served" Plugin ID locking bound to `repository_url`.
  - Implement the github release and repository update logic.
  - Make sure no older logic is broken so that both new and old plugin submission workflow can work side by side till the new one is ready to merge.

- **Deliverable:** The core GitHub Actions workflow (Review, Build, Publish, Error Recovery) is functional.

### Milestone 4: Validation & Tuning (Top 20 + Threats)

- **Tasks:**
  - Run the scanner against the Top 20 Joplin plugins. Adjust rules to ensure zero false positives.
  - Deploy 5-10 test malicious plugins covering the Phase 1 & Phase 2 Threat Model to verify 100% catch rate.

- **Deliverable:** Documented proof of scanner accuracy and a video showing the complete workflow
    - A developer runs npm run publish on a fresh plugin
    - The issue is created on the repository
    - The workflows run and check the plugin
    - A report is generated for reviewers
    - The reviewer approve the plugin with a "status: approved" label (for example)
    - The .jpl artifact appears on the test registry's "plugins" folder
    - The manifests.json file is updated with the new plugin entry

---

## 3. UPCOMMING WEEK SHEDULE :

We have 2 PR's to merge :

- 1 in `generator-joplin`
- 1 in `plugin-repo-cli`

### Week 7 - 8 :

With the end of week 6 we have a complete scanning pipeline to test with custom plugins.
In week 7, I will create custom plugins that will target the rules intentionally 3-4 rules per plugin to check if the rules are working properly. In case of any changed in the rule, I will retest all the 20 recommended joplin plugins again.

Here on we can also focus on getting the PR for `plugin-repo-cli` merge as the registry update workflow will depend on this pr.

### Week 9 :

With the end of week 8 all the testing will be completed and we will have rules that does what their description says. I will update the official `Plugins-test` repository with the scanning logic and open the test issues for all the test plugin I wrote in the official repository for logs.

I will start working on the update registry workflow with the intented logic (predicting that the pr for `plugin-repo-cli` was merged).

### Week 10 - 12 :

With the end of week 9 we will have the logic for the update registry workflow implemented and ready for testing. Now we can be focused on testing the whole scanning + update workflow.

In parallel, from here on we can focus on getting the last pr for `generator-joplin` merged, this can be done at last as it does not conflict or block any of the other code.

---

## 4. DELIVERABLE DATE :

### 24 july : 
- Finalize the code for plugin-repo-cli.
- Get the plugin-repo-cli code merged.
- Test the scan on the rest of the **Recommended** Plugins

### 2 August : 
- Get the top 20 plugins test workflow running (Which will run whenever there is change in codeql rules and it should find no findings)
- Get the update repository manifest, README, github release and plugins folder update workflow done.

### 10 August : 
- Get the 2nd half of the `generator-joplin` code merged

### 14 August : 
- Do the final set of testings and record a video with the whole workflow  
- Merge all the local code to the official plugins-test repository.
- Open issues on the official repository with test-plugins to test the final workflow 
- Deliver the video showing the whole workflow working correctly
### 
---

## 5. Threat Model and Rules Summary

CodeQl will be used to evaluate plugins against these rules : [RULES.md](.github\codeql\rules.md)
