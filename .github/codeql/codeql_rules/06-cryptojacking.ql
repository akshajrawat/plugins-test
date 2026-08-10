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

predicate executesArgumentListAsShell(SystemCommandExecution execution) {
  execution.getOptionsArg()
      .getALocalSource()
      .getAPropertyWrite("shell")
      .getRhs()
      .asExpr()
      .(BooleanLiteral)
      .getBoolValue() = true
  or
  exists(API::Node options |
    options.asSink() = execution.getOptionsArg() and
    options.getMember("shell").asSink().mayHaveBooleanValue(true)
  )
}

predicate isShellInterpretedCommandInput(DataFlow::Node sink) {
  exists(SystemCommandExecution execution |
    (sink = execution.getACommandArgument() or sink = execution.getArgumentList()) and
    (execution.isShellInterpreted(sink) or executesArgumentListAsShell(execution))
  )
}

predicate isFileWrite(DataFlow::Node data, DataFlow::Node path) {
  exists(FileSystemWriteAccess access |
    data = access.getADataNode() and
    path = access.getAPathArgument()
  )
  or
  exists(DataFlow::CallNode call, string moduleName |
    moduleName in ["fs", "node:fs", "fs/promises", "node:fs/promises", "fs-extra"] and
    call = DataFlow::moduleMember(moduleName, _).getACall() and
    call.getCalleeName() in [
      "writeFile", "writeFileSync", "appendFile", "appendFileSync",
      "outputFile", "outputFileSync"
    ] and
    path = call.getArgument(0) and
    data = call.getArgument(1)
  )
}

predicate isDownloadedFileDataExecuted(DataFlow::Node data, DataFlow::Node command) {
  exists(DataFlow::Node path, SystemCommandExecution execution |
    isFileWrite(data, path) and
    command = execution.getACommandArgument() and
    command.getALocalSource() = path.getALocalSource()
  )
}

module CryptojackingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    Joplin::isRemoteDataSource(source) or
    isCryptominingIndicator(source)
  }

  predicate isSink(DataFlow::Node sink) {
    isCommandInput(sink) or
    isFileWrite(sink, _)
  }
}

module CryptojackFlow = TaintTracking::Global<CryptojackingConfig>;
import CryptojackFlow::PathGraph

from
  CryptojackFlow::PathNode source,
  CryptojackFlow::PathNode sink,
  DataFlow::Node reportedNode,
  string msg
where
  CryptojackFlow::flowPath(source, sink) and
  (
    (reportedNode = sink.getNode() and isCommandInput(reportedNode)) or
    isDownloadedFileDataExecuted(sink.getNode(), reportedNode)
  ) and
  (
    if isShellInterpretedCommandInput(reportedNode)
    then msg = "The plugin is passing remote data or a cryptocurrency-mining indicator to a shell-interpreted command. Shell interpretation can treat metacharacters as additional commands. Verify the command input for malware or resource hijacking."
    else msg = "The plugin is passing remote data or a cryptocurrency-mining indicator to an operating-system command or its argument list. Verify that it is not executing a downloaded payload or hijacking system resources."
  )
select reportedNode, source, sink, msg
