/**
 * @name Native Binary Dropping & Cryptojacking
 * @description Detects remote payloads or cryptocurrency-mining indicators reaching operating-system command execution.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin cryptojacking
 * @id js/joplin/cryptojacking
 */
import javascript
import JoplinSources

predicate isCryptominingIndicator(DataFlow::Node source) {
  exists(string value |
    value = source.getStringValue() and
    value.regexpMatch("(?i).*(xmrig|minerd|ethminer|cgminer|t-rex|nsfminer|pool\\.|stratum\\+tcp|nicehash).*")
  )
}

predicate isCommandInput(DataFlow::Node sink) {
  exists(SystemCommandExecution execution |
    sink = execution.getACommandArgument() or
    sink = execution.getArgumentList()
  )
}

predicate isShellInterpretedCommandInput(DataFlow::Node sink) {
  exists(SystemCommandExecution execution |
    (sink = execution.getACommandArgument() or sink = execution.getArgumentList()) and
    execution.isShellInterpreted(sink)
  )
}

module CryptojackingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    Joplin::isRemoteDataSource(source) or
    isCryptominingIndicator(source)
  }

  predicate isSink(DataFlow::Node sink) {
    isCommandInput(sink)
  }
}

module CryptojackFlow = TaintTracking::Global<CryptojackingConfig>;
import CryptojackFlow::PathGraph

from CryptojackFlow::PathNode source, CryptojackFlow::PathNode sink, string msg
where CryptojackFlow::flowPath(source, sink) and
  (
    if isShellInterpretedCommandInput(sink.getNode())
    then msg = "The plugin is passing remote data or a cryptocurrency-mining indicator to a shell-interpreted command. Shell interpretation can treat metacharacters as additional commands. Verify the command input for malware or resource hijacking."
    else msg = "The plugin is passing remote data or a cryptocurrency-mining indicator to an operating-system command or its argument list. Verify that it is not executing a downloaded payload or hijacking system resources."
  )
select sink.getNode(), source, sink, msg
