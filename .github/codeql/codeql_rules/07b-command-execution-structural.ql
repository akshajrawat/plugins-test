/**
 * @name Command Execution (Structural)
 * @description Detects operating-system command execution using hardcoded command strings.
 * @kind problem
 * @problem.severity warning
 * @tags security joplin-plugin command-execution
 * @id js/joplin/command-execution-structural
 */
import javascript

predicate hasCryptominingIndicator(SystemCommandExecution execution) {
  exists(string value |
    (
      value = execution.getACommandArgument().getALocalSource().getStringValue() or
      value = execution.getArgumentList().getALocalSource().asExpr().(ArrayExpr).getAnElement().getStringValue()
    ) and
    value.regexpMatch("(?i).*(xmrig|minerd|ethminer|cgminer|t-rex|nsfminer|pool\\.|stratum\\+tcp|nicehash).*")
  )
}

predicate hardcodedCommandValue(DataFlow::Node command, string value) {
  value = command.getStringValue() or
  value = command.getALocalSource().getStringValue()
}

from SystemCommandExecution execution, DataFlow::Node command, string commandValue
where
  command = execution.getACommandArgument() and
  hardcodedCommandValue(command, commandValue) and
  not hasCryptominingIndicator(execution)
select command, "Terminal Command Execution (Hardcoded): A hardcoded operating-system command is executed. Review the command and its arguments to confirm that invoking native processes is required and safe."
