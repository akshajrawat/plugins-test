/**
 * @name Command Execution (Structural)
 * @description Detects execution of terminal commands using hardcoded string literals.
 * @kind problem
 * @problem.severity warning
 * @tags security joplin-plugin command-execution
 * @id js/joplin/command-execution-structural
 */
import javascript
import JoplinSinks

from DataFlow::Node cmdSink, string cmdString
where
  isCommandExecutionSink(cmdSink) and
  cmdString = cmdSink.getStringValue() and
  not cmdString.regexpMatch("(?i).*(xmrig|minerd|ethminer|cgminer|t-rex|nsfminer|pool\\.|stratum\\+tcp|nicehash).*")
select cmdSink, "Terminal Command Execution (Hardcoded): A hardcoded string command is passed to a child process. Review the executed command to ensure it does not execute unauthorized native logic or binaries."
