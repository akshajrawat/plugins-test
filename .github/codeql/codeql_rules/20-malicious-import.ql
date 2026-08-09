/**
 * @name Malicious Import Module
 * @description Detects imported file paths or contents flowing to network, command, or unsafe filesystem destinations.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin malicious-import
 * @id joplin/malicious-import
 */
import javascript
import JoplinSinks
import JoplinSources

predicate isImportModuleRegistration(DataFlow::MethodCallNode reg) {
  reg.getMethodName() = "registerImportModule" and
  reg.getReceiver().getALocalSource() = Joplin::interop()
}

predicate isImportModuleDefinition(DataFlow::MethodCallNode reg, DataFlow::SourceNode def) {
  def = reg.getArgument(0).getALocalSource()
  or
  exists(DataFlow::CallNode factoryCall, DataFlow::FunctionNode factory |
    factoryCall = reg.getArgument(0).getALocalSource() and
    factory = factoryCall.getCalleeNode().getAFunctionValue() and
    def = factory.getAReturn().getALocalSource()
  )
}

predicate isImportModuleCallback(DataFlow::FunctionNode fn) {
  exists(DataFlow::MethodCallNode reg, DataFlow::SourceNode def |
    isImportModuleRegistration(reg) and
    isImportModuleDefinition(reg, def) and
    fn = def.getAPropertyWrite("onExec").getRhs().getAFunctionValue()
  )
  or
  exists(DataFlow::MethodCallNode reg, DataFlow::NewNode instance, DataFlow::ClassNode cls |
    isImportModuleRegistration(reg) and
    instance = reg.getArgument(0) and
    (
      cls = instance.getCalleeNode().getALocalSource() or
      cls.getConstructor() = instance.getCalleeNode().getAFunctionValue() or
      (
        cls.getName() = instance.getCalleeName() and
        cls.getFile() = instance.getFile()
      )
    ) and
    fn = cls.getInstanceMethod("onExec")
  )
}

predicate isNodeOrExtraFileCall(DataFlow::CallNode call, string method) {
  exists(string moduleName |
    moduleName in ["fs", "node:fs", "fs/promises", "node:fs/promises", "fs-extra"] and
    call = DataFlow::moduleMember(moduleName, method).getACall()
  )
  or
  call = DataFlow::moduleImport(["fs", "node:fs"]).getAPropertyRead("promises").getAMethodCall(method)
  or
  exists(DataFlow::MethodCallNode methodCall |
    call = methodCall and
    isJoplinFsExtraCall(methodCall) and
    methodCall.getMethodName() = method
  )
}

predicate isSupportedFileRead(DataFlow::CallNode call) {
  isNodeOrExtraFileCall(call, ["readFile", "readFileSync", "readJSON", "readJSONSync"])
}

predicate isSupportedReadStream(DataFlow::CallNode call) {
  isNodeOrExtraFileCall(call, "createReadStream")
}

predicate isSupportedFileWrite(
  DataFlow::CallNode call, DataFlow::Node path, DataFlow::Node content
) {
  isNodeOrExtraFileCall(
    call,
    ["writeFile", "writeFileSync", "appendFile", "appendFileSync", "outputFile", "outputFileSync"]
  ) and
  path = call.getArgument(0) and
  content = call.getArgument(1)
}

predicate isSupportedFileCopy(
  DataFlow::CallNode call, DataFlow::Node source, DataFlow::Node destination
) {
  isNodeOrExtraFileCall(call, ["copyFile", "copyFileSync", "copy", "copySync"]) and
  source = call.getArgument(0) and
  destination = call.getArgument(1)
}

predicate isSupportedFileMove(
  DataFlow::CallNode call, DataFlow::Node source, DataFlow::Node destination
) {
  isNodeOrExtraFileCall(call, ["move", "moveSync", "rename", "renameSync"]) and
  source = call.getArgument(0) and
  destination = call.getArgument(1)
}

predicate isSupportedWriteStream(DataFlow::CallNode call, DataFlow::Node destination) {
  isNodeOrExtraFileCall(call, "createWriteStream") and
  destination = call.getArgument(0)
}

predicate isStreamTransfer(
  DataFlow::Node content, DataFlow::Node destination
) {
  exists(DataFlow::MethodCallNode pipe, DataFlow::CallNode output |
    pipe.getMethodName() = "pipe" and
    isSupportedWriteStream(output, destination) and
    pipe.getArgument(0).getALocalSource() = output.getALocalSource() and
    content = pipe.getReceiver()
  )
  or
  exists(DataFlow::CallNode pipeline, DataFlow::CallNode output, string moduleName |
    moduleName in ["stream", "node:stream", "stream/promises", "node:stream/promises"] and
    pipeline = DataFlow::moduleMember(moduleName, "pipeline").getACall() and
    output.getALocalSource() = pipeline.getArgument(1).getALocalSource() and
    isSupportedWriteStream(output, destination) and
    content = pipeline.getArgument(0)
  )
}

predicate isFileMutationTarget(DataFlow::Node target) {
  exists(DataFlow::CallNode call, DataFlow::Node content |
    isSupportedFileWrite(call, target, content)
  )
  or
  exists(DataFlow::CallNode call, DataFlow::Node source |
    isSupportedFileCopy(call, source, target) or
    isSupportedFileMove(call, source, target)
  )
  or
  exists(DataFlow::Node content | isStreamTransfer(content, target))
}

module ImportDataDirConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = Joplin::joplin().getAPropertyRead("plugins").getAMethodCall("dataDir")
  }

  predicate isSink(DataFlow::Node sink) {
    isFileMutationTarget(sink) or
    sink = DataFlow::moduleMember(["path", "node:path"], "dirname").getACall()
  }
}

module ImportDataDirFlow = TaintTracking::Global<ImportDataDirConfig>;

predicate hasParentDirectorySegment(DataFlow::Node destination) {
  exists(DataFlow::Node partNode, Expr part, string value |
    (
      part = destination.asExpr().getAChildExpr*()
      or
      part = destination.getALocalSource().asExpr().getAChildExpr*()
      or
      partNode = destination.getAPredecessor*() and
      part = partNode.asExpr().getAChildExpr*()
    ) and
    part.mayHaveStringValue(value) and
    (
      value = ".." or
      value.regexpMatch("\\.\\.[/\\\\].*") or
      value.regexpMatch(".*[/\\\\]\\.\\.([/\\\\].*)?")
    )
  )
}

predicate hasUnsafePathTransformation(DataFlow::Node destination) {
  exists(DataFlow::CallNode call |
    call.flowsTo(destination) and
    (
      call = DataFlow::moduleMember(["path", "node:path"], "dirname").getACall()
      or
      call = DataFlow::moduleMember(["path", "node:path"], "resolve").getACall() and
      exists(string value |
        call.getAnArgument().mayHaveStringValue(value) and
        value.regexpMatch("^(/|\\\\\\\\|[a-zA-Z]:[/\\\\]).*")
      )
    )
  )
}

predicate isAuthorizedImportDestination(DataFlow::Node destination) {
  ImportDataDirFlow::flow(_, destination) and
  not hasParentDirectorySegment(destination) and
  not hasUnsafePathTransformation(destination)
}

predicate isUnsafeFileSink(DataFlow::Node sink) {
  exists(DataFlow::CallNode call, DataFlow::Node path, DataFlow::Node content |
    isSupportedFileWrite(call, path, content) and
    not isAuthorizedImportDestination(path) and
    (sink = path or sink = content)
  )
  or
  exists(DataFlow::CallNode call, DataFlow::Node source, DataFlow::Node destination |
    isSupportedFileCopy(call, source, destination) and
    not isAuthorizedImportDestination(destination) and
    (sink = source or sink = destination)
  )
  or
  exists(DataFlow::CallNode call, DataFlow::Node source, DataFlow::Node destination |
    isSupportedFileMove(call, source, destination) and
    (sink = source or sink = destination)
  )
  or
  exists(DataFlow::Node content, DataFlow::Node destination |
    isStreamTransfer(content, destination) and
    not isAuthorizedImportDestination(destination) and
    sink = content
  )
}

predicate isCommandArgumentArrayElement(DataFlow::Node sink) {
  exists(DataFlow::CallNode call, DataFlow::ArrayCreationNode arguments, string moduleName |
    moduleName in ["child_process", "node:child_process"] and
    call = DataFlow::moduleMember(moduleName, ["execFile", "execFileSync", "spawn", "spawnSync", "fork"]).getACall() and
    arguments = call.getArgument(1).getALocalSource() and
    sink = arguments.getAnElement()
  )
}

module MaliciousImportConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::FunctionNode fn |
      isImportModuleCallback(fn) and
      source = fn.getParameter(0).getAPropertyRead("sourcePath")
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(DataFlow::CallNode readCall |
      isSupportedFileRead(readCall) and
      node1 = readCall.getArgument(0) and
      (
        node2 = readCall
        or
        exists(int callbackIndex, DataFlow::FunctionNode callback |
          callbackIndex in [1, 2] and
          callback = readCall.getArgument(callbackIndex).getAFunctionValue() and
          node2 = callback.getParameter(1)
        )
      )
    )
    or
    exists(DataFlow::CallNode stream |
      isSupportedReadStream(stream) and
      node1 = stream.getArgument(0) and
      node2 = stream
    )
    or
    exists(
      DataFlow::CallNode stream,
      DataFlow::MethodCallNode listener,
      DataFlow::FunctionNode callback
    |
      isSupportedReadStream(stream) and
      listener.getReceiver().getALocalSource*() = stream and
      listener.getMethodName() = "on" and
      listener.getArgument(0).getStringValue() = "data" and
      callback = listener.getArgument(1).getAFunctionValue() and
      node1 = stream.getArgument(0) and
      node2 = callback.getParameter(0)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    isNetworkExfiltrationSink(sink) or
    isCommandExecutionSink(sink) or
    isCommandArgumentArrayElement(sink) or
    isUnsafeFileSink(sink)
  }
}

module MaliciousImportFlow = TaintTracking::Global<MaliciousImportConfig>;
import MaliciousImportFlow::PathGraph

from MaliciousImportFlow::PathNode source, MaliciousImportFlow::PathNode sink
where MaliciousImportFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Malicious Import Processing: An imported file path or its contents are flowing into a network request, terminal command, source-file mutation, or filesystem destination outside `joplin.plugins.dataDir()`. Verify that the import remains local and only creates expected Joplin data or files inside the plugin data directory."
