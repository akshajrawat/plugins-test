/**
 * Common sink definitions for Joplin security rules.
 */
import javascript
import JoplinSources

/**
 * Identifies sinks related to operating system command execution or child processes.
 */
predicate isCommandExecutionSink(DataFlow::Node sink) {
  sink instanceof SystemCommandExecution
}

/**
 * Identifies command argument nodes for operating system command execution or child processes.
 */
predicate isCommandExecutionArgumentSink(DataFlow::Node sink) {
  exists(SystemCommandExecution exec |
    sink = exec.getACommandArgument()
  )
}

/**
 * Identifies sinks related to file system writes and destructive manipulations.
 */
predicate isFileSystemPathSink(DataFlow::Node sink) {
  sink = any(FileSystemWriteAccess acc).getAPathArgument() or
  exists(DataFlow::CallNode call, string moduleName |
    (moduleName = "fs" or moduleName = "fs-extra" or moduleName = "node:fs" or moduleName = "node:fs/promises" or moduleName = "fs/promises") and
    call = DataFlow::moduleMember(moduleName, _).getACall() and
    call.getCalleeName() in [
      "writeFile", "writeFileSync",
      "appendFile", "appendFileSync"
    ] and
    sink = call.getArgument(0)
  ) or
  exists(DataFlow::MethodCallNode mc |
    mc.getMethodName() = "archiveExtract" and
    mc.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("fs") and
    sink = mc.getArgument(1)
  ) or
  exists(DataFlow::CallNode call |
    call.getCalleeName() in [
      "outputFile", "outputFileSync",
      "move", "moveSync",
      "copyFile", "copyFileSync",
      "copy", "copySync",
      "remove", "removeSync",
      "emptyDir", "emptyDirSync",
      "ensureFile", "ensureFileSync",
      "ensureDir", "ensureDirSync",
      "unlink", "unlinkSync",
      "rm", "rmSync",
      "rmdir", "rmdirSync",
      "rename", "renameSync",
      "chmod", "chmodSync"
    ] and
    (sink = call.getArgument(0) or sink = call.getArgument(1)) // move/copy take 2 path arguments usually
  )
}

/**
 * Identifies sinks related to file system writes where data is being written (argument 1).
 */
predicate isFileSystemDataSink(DataFlow::Node sink) {
  sink = any(FileSystemWriteAccess acc).getADataNode() or
  exists(DataFlow::CallNode call, string moduleName |
    (moduleName = "fs" or moduleName = "fs-extra" or moduleName = "node:fs" or moduleName = "node:fs/promises" or moduleName = "fs/promises") and
    call = DataFlow::moduleMember(moduleName, _).getACall() and
    call.getCalleeName() in [
      "writeFile", "writeFileSync",
      "appendFile", "appendFileSync",
      "outputFile", "outputFileSync"
    ] and
    sink = call.getArgument(1)
  )
}

/**
 * Holds if `call` sends data over the network via fetch, axios, http, https, net, tls, websockets, or webview messaging.
 */
predicate isNetworkExfiltrationCall(DataFlow::CallNode call) {
  call instanceof ClientRequest
}

/**
 * Identifies node arguments that flow into network/exfiltration sinks.
 */
predicate isNetworkExfiltrationSink(DataFlow::Node sink) {
  exists(ClientRequest cr | sink = cr.getADataNode() or sink = cr.getUrl())
}

/**
 * Identifies sinks related to Joplin-specific storage (e.g. joplin.data.put) and views (e.g. setHtml).
 */
predicate isJoplinSpecificSink(DataFlow::Node sink) {
  exists(DataFlow::CallNode call | 
    (call.getCalleeName() = "put" and call.getReceiver().getALocalSource() = Joplin::data() and sink = call.getArgument(2)) or
    (call.getCalleeName() = "post" and call.getReceiver().getALocalSource() = Joplin::data() and sink = call.getArgument(2)) or
    (call.getCalleeName() = "setHtml" and call.getReceiver().getALocalSource() = Joplin::panels() and sink = call.getArgument(1)) or
    (call.getCalleeName() = "setHtml" and call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs") and sink = call.getArgument(1)) or
    (call.getCalleeName() = "setHtml" and call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("editors") and sink = call.getArgument(1)) or
    (call.getCalleeName() = "userDataSet" and call.getReceiver().getALocalSource() = Joplin::data() and sink = call.getArgument(3))
  )
}

/**
 * Identifies Joplin cross-boundary message passing sinks.
 */
predicate isJoplinMessageSink(DataFlow::Node sink) {
  exists(DataFlow::MethodCallNode call |
    call.getMethodName() = "postMessage" and
    (
      call.getReceiver().getALocalSource() = Joplin::panels() or
      call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs")
    ) and
    sink = call.getArgument(1)
  )
}
