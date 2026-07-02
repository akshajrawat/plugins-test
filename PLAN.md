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

### Milestone 1: CLI & Authentication Transition

- **Tasks:**
  - Make sure that the code user is submitting is not broken and has a valid public repository on github.
  - Implement GitHub Device Flow in `generator-joplin` for developer authentication.
  - Generate GitHub Issues for new plugin submissions with a structured json.

- **Deliverable:** Developers can run `npm run publish` to authenticate and securely open a submission issue on the test repository.

### Milestone 2: SAST Scanning using CodeQl and Repository update

- **Tasks:**
  - Integrate the CodeQl scanner with custom rules using our threat model.
  - Run the tests on top 20 joplin plugin to minimize false positives.
  - Build the workflow YAML so that every new open issue with [Plugin Submission] in the title runs through an automated scanning workflow and generates a scanning report as a comment.
  - When the accepted label is added to the issue it runs through another workflow to update the repository with the accepted plugin data.
  - Implement the **Split-Job Architecture**:
    1. _Build Job:_ Builds the untrusted code and run it through scan for the report.
    2. _Publish Job:_ Triggered by `status: approved` label; uploads `.jpl` to GitHub Releases and the `/plugin` folder in the repository.
- **Deliverable:** Automated, structured security reports posted directly to submission issues comments, after review is done add `status: approved` label to get the plugin into the repository.

### Milestone 3: Joplin Plugin Cli update

- **Tasks:**
  - Implement "First-Come, First-Served" Plugin ID locking bound to `repository_url`.
  - Implement the github release and repository update logic.
  - Make sure no older logic is broken so that both new and old plugin submission workflow can work side by side till the new one is ready to merge.

- **Deliverable:** The core GitHub Actions workflow (Review, Build, Publish, Error Recovery) is functional.

### Milestone 4: Validation & Tuning (Top 20 + Threats)

- **Tasks:**
  - Run the scanner against the Top 20 Joplin plugins. Adjust rules to ensure close to zero false positives.
  - Deploy 5-10 test malicious plugins covering the Phase 1 & Phase 2 Threat Model to verify 100% catch rate.

- **Deliverable:** Documented proof of scanner accuracy and PoC readiness for maintainer evaluation.

---

## 4. Threat Model and Rules Summary

CodeQl will be used to evaluate plugins against these rules : [RULES.md](.github\codeql\rules.md)
