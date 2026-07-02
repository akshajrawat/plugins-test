# This file will contain some additional information about the scan

1. [plugins-test\scripts\code-scan\scanReport.ts](plugins-test\scripts\code-scan\scanReport.ts) : This file contains the logic of extracting data from the SARIF JSON and form a report to post on the issue comment.

2. [plugins-test\scripts\code-scan\scanManager.ts](plugins-test\scripts\code-scan\scanManager.ts) : This file contains the logic that helps in :
   - Parsing the issue body.
   - Generating and updating comment on the issue.
   - Submission of the final report to the issue comment.

# CodeQl :

CodeQl gives result in form of SARIF file. We parse that file to json to get the data we need.
Here is a simplified example of what that SARIF JSON structure actually looks like :

```
    {
      "version": "2.1.0",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "CodeQL",
              "rules": [
                {
                  "id": "js/syntax-error",
                  "shortDescription": { "text": "Syntax error" },
                  "defaultConfiguration": { "level": "error" }
                }
              ]
            },
            "extensions": [
              {
                "name": "Joplin Security Queries",
                "rules": [
                  {
                    "id": "js/joplin/secret-key-theft",
                    "shortDescription": { "text": "Sensitive key exposed to network" },
                    "properties": {
                      "problem.severity": "error"
                    }
                  }
                ]
              }
            ]
          },
          "results": [
            {
              "ruleId": "js/joplin/secret-key-theft",
              "message": { "text": "Data Exfiltration Warning..." }
              "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "/home/runner/work/plugins-test/target-plugin/src/vulnerability.ts"
                        },
                        "region": {
                            "startLine": 57,
                            "startColumn": 12,
                            "endLine": 57,
                            "endColumn": 40
                        }
                    }
                }
              ]
            },
          ]
        },
      ]
    }
```
