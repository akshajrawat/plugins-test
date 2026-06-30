/**
 * Common sink definitions for Joplin security rules.
 */
import javascript
import JoplinSources

/**
   * Identifies sinks related to operating system command execution or child processes.
   */
  predicate isCommandExecutionSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call, string moduleName, string methodName |
      (moduleName = "child_process" or moduleName = "node:child_process") and
      (
        methodName = "exec" or methodName = "execFile" or methodName = "spawn" or
        methodName = "execSync" or methodName = "execFileSync" or methodName = "spawnSync" or
        methodName = "fork"
      ) and
      call = DataFlow::moduleMember(moduleName, methodName).getACall()
    |
      sink = call.getArgument(0) or
      sink = call.getArgument(1)
    )
  }

  /**
   * Identifies sinks related to file system writes and destructive manipulations.
   */
  predicate isFileSystemPathSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call, string moduleName | 
      (moduleName = "fs" or moduleName = "fs-extra" or moduleName = "node:fs" or moduleName = "node:fs/promises" or moduleName = "fs/promises") and
      call = DataFlow::moduleMember(moduleName, _).getACall() and
      call.getCalleeName() in [
        "writeFile", "writeFileSync", "appendFile", "appendFileSync",
        "rename", "renameSync", "copyFile", "copyFileSync",
        "unlink", "unlinkSync",
        "chmod", "chmodSync",
        "mkdir", "mkdirSync",
        "createWriteStream",
        "rm", "rmSync", "rmdir", "rmdirSync",
        "truncate", "truncateSync",
        "symlink", "symlinkSync", "link", "linkSync",
        "remove", "removeSync",
        "move", "moveSync",
        "copy", "copySync",
        "emptyDir", "emptyDirSync",
        "outputFile", "outputFileSync",
        "write", "writeSync", "ftruncate", "ftruncateSync"
      ]
    |
      sink = call.getArgument(0)
    )
  }

  /**
   * Identifies sinks related to file system writes where data is being written (argument 1).
   */
  predicate isFileSystemDataSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call, string moduleName | 
      (moduleName = "fs" or moduleName = "fs-extra" or moduleName = "node:fs" or moduleName = "node:fs/promises" or moduleName = "fs/promises") and
      call = DataFlow::moduleMember(moduleName, _).getACall() and
      call.getCalleeName() in [
        "writeFile", "writeFileSync", "appendFile", "appendFileSync",
        "outputFile", "outputFileSync"
      ]
    |
      sink = call.getArgument(1)
    )
  }

  /**
   * Holds if `call` sends data over the network via fetch, axios, http, https, net, tls, websockets, or webview messaging.
   */
  predicate isNetworkExfiltrationCall(DataFlow::CallNode call) {
    call = DataFlow::globalVarRef("fetch").getACall() or
    call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("axios", _) or
    call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("https", "request") or
    call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("http", "request") or
    call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("net", "connect") or
    call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("tls", "connect") or
    (
      call.getCalleeName() = "send" and
      exists(DataFlow::NewNode nw | call.getReceiver().getALocalSource() = nw and nw.getCalleeName() = "WebSocket")
    ) or
    (
      call.getCalleeName() = "postMessage" and
      (
        not exists(call.getReceiver()) or
        call.getReceiver() = DataFlow::globalVarRef("window") or
        exists(DataFlow::NewNode nw | call.getReceiver().getALocalSource() = nw and nw.getCalleeName() = "Worker")
      )
    )
  }

  /**
   * Identifies node arguments that flow into network/exfiltration sinks.
   */
  predicate isNetworkExfiltrationSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      isNetworkExfiltrationCall(call)
    |
      sink = call.getAnArgument()
    )
  }

  /**
   * Identifies sinks related to Joplin-specific storage (e.g. joplin.data.put) and views (e.g. setHtml).
   */
  predicate isJoplinSpecificSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call | 
      (call.getCalleeName() = "put" and call.getReceiver().getALocalSource() = Joplin::data()) or
      (call.getCalleeName() = "setHtml" and call.getReceiver().getALocalSource() = Joplin::panels()) or
      (call.getCalleeName() = "setHtml" and call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs")) or
      (call.getCalleeName() = "register" and call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("contentScripts")) or
      (call.getCalleeName() = "userDataSet" and call.getReceiver().getALocalSource() = Joplin::data())
    | 
      sink = call.getAnArgument()
    )
  }
