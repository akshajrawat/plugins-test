/**
 * Shared definitions for Joplin Plugin CodeQL rules.
 */
import javascript
import JoplinLinks

module Joplin {
  /** Gets a reference to the global `joplin` object or api module import. */
  DataFlow::SourceNode joplin() {
    result = DataFlow::globalVarRef("joplin") or
    result = DataFlow::moduleImport("api")
  }

  /** Gets a reference to `joplin.settings`. */
  DataFlow::SourceNode settings() {
    result = joplin().getAPropertyRead("settings")
  }

  /** Gets a reference to `joplin.data`. */
  DataFlow::SourceNode data() {
    result = joplin().getAPropertyRead("data")
  }

  /** Gets a reference to `joplin.clipboard`. */
  DataFlow::SourceNode clipboard() {
    result = joplin().getAPropertyRead("clipboard")
  }

  /** Gets a reference to `joplin.workspace`. */
  DataFlow::SourceNode workspace() {
    result = joplin().getAPropertyRead("workspace")
  }

  /** Gets a reference to `joplin.views.panels`. */
  DataFlow::SourceNode panels() {
    result = joplin().getAPropertyRead("views").getAPropertyRead("panels")
  }

  /** Gets a reference to `joplin.views.editors`. */
  DataFlow::SourceNode editors() {
    result = joplin().getAPropertyRead("views").getAPropertyRead("editors")
  }

  /** Gets a reference to `joplin.views.dialogs`. */
  DataFlow::SourceNode dialogs() {
    result = joplin().getAPropertyRead("views").getAPropertyRead("dialogs")
  }

  /** Gets a reference to `joplin.filters`. */
  DataFlow::SourceNode filters() {
    result = joplin().getAPropertyRead("filters")
  }

  /** Gets a reference to `joplin.contentScripts`. */
  DataFlow::SourceNode contentScripts() {
    result = joplin().getAPropertyRead("contentScripts")
  }

  /** Gets a reference to `joplin.interop`. */
  DataFlow::SourceNode interop() {
    result = joplin().getAPropertyRead("interop")
  }

  /** Gets a call to `joplin.require`. */
  DataFlow::CallNode require(string moduleName) {
    result.getCalleeName() = "require" and
    result.getReceiver().getALocalSource() = joplin() and
    result.getArgument(0).getStringValue() = moduleName
  }

  /** Gets a call to `joplin.settings.globalValue` or `globalValues`. */
  DataFlow::CallNode settingsGlobalValue() {
    result.getReceiver().getALocalSource() = settings() and
    (result.getCalleeName() = "globalValue" or result.getCalleeName() = "globalValues")
  }

  bindingset[setting]
  predicate isSensitiveSetting(string setting) {
    setting.regexpMatch("sync\\..*\\.auth") or
    setting.regexpMatch("sync\\..*\\.context") or
    setting.regexpMatch("sync\\..*\\.password") or
    setting.regexpMatch("sync\\..*\\.username") or
    setting.regexpMatch("sync\\..*\\.userEmail") or
    setting in [
      "api.token", "syncInfoCache", "clientId", "sync.userId", 
      "encryption.masterPassword", "encryption.cachedPpk", "encryption.passwordCache"
    ]
  }

  /** Identifies messages received from panel, editor, and content-script webviews. */
  predicate isJoplinMessageSource(DataFlow::Node source) {
    exists(DataFlow::MethodCallNode onMessageCall, DataFlow::FunctionNode callback |
      onMessageCall.getMethodName() = "onMessage" and
      (
        onMessageCall.getReceiver().getALocalSource() = panels() or
        onMessageCall.getReceiver().getALocalSource() = editors() or
        onMessageCall.getReceiver().getALocalSource() = contentScripts()
      ) and
      callback = onMessageCall.getArgument(1).getAFunctionValue() and
      source = callback.getParameter(0)
    )
  }

  /**
   * Identifies sources of remote external data (fetch, axios, http, etc).
   */
  predicate isNodeHttpRequestCall(DataFlow::CallNode call) {
    call = DataFlow::moduleMember("http", "get").getACall() or
    call = DataFlow::moduleMember("http", "request").getACall() or
    call = DataFlow::moduleMember("https", "get").getACall() or
    call = DataFlow::moduleMember("https", "request").getACall() or
    call = DataFlow::moduleMember("node:http", "get").getACall() or
    call = DataFlow::moduleMember("node:http", "request").getACall() or
    call = DataFlow::moduleMember("node:https", "get").getACall() or
    call = DataFlow::moduleMember("node:https", "request").getACall()
  }

  predicate isNodeHttpResponseSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call, DataFlow::FunctionNode callback |
      isNodeHttpRequestCall(call) and
      callback = call.getLastArgument().getAFunctionValue() and
      source = callback.getParameter(0)
    )
  }

  predicate isNodeHttpResponseChunkSource(DataFlow::Node source) {
    exists(
      DataFlow::Node response,
      DataFlow::MethodCallNode onCall,
      DataFlow::FunctionNode callback
    |
      isNodeHttpResponseSource(response) and
      onCall.getReceiver().getALocalSource*() = response and
      onCall.getMethodName() = "on" and
      onCall.getArgument(0).getStringValue() = "data" and
      callback = onCall.getArgument(1).getAFunctionValue() and
      source = callback.getParameter(0)
    )
  }

  predicate isAxiosClient(DataFlow::Node client) {
    client = DataFlow::moduleImport("axios") or
    client = DataFlow::moduleImport("axios").getAMethodCall("create")
  }

  predicate isAxiosRequestCall(DataFlow::CallNode call) {
    call = DataFlow::moduleImport("axios").getACall() or
    exists(DataFlow::MethodCallNode methodCall |
      call = methodCall and
      isAxiosClient(methodCall.getReceiver().getALocalSource()) and
      methodCall.getMethodName() in [
        "get", "post", "put", "patch", "delete", "head", "options", "request"
      ]
    )
  }

  predicate isGotRequestCall(DataFlow::CallNode call) {
    call = DataFlow::globalVarRef("got").getACall() or
    call = DataFlow::moduleImport("got").getACall() or
    exists(DataFlow::MethodCallNode methodCall |
      call = methodCall and
      methodCall.getReceiver().getALocalSource() = DataFlow::moduleImport("got") and
      methodCall.getMethodName() in ["get", "post", "put", "patch", "delete", "head"]
    )
  }

  predicate isSuperagentRequestCall(DataFlow::CallNode call) {
    exists(DataFlow::MethodCallNode methodCall |
      call = methodCall and
      methodCall.getReceiver().getALocalSource() = DataFlow::moduleImport("superagent") and
      methodCall.getMethodName() in ["get", "post", "put", "patch", "delete", "head"]
    )
  }

  predicate isSuperagentResponseSource(DataFlow::Node source) {
    exists(
      DataFlow::CallNode request,
      DataFlow::MethodCallNode deliveryCall,
      DataFlow::FunctionNode callback
    |
      isSuperagentRequestCall(request) and
      deliveryCall.getReceiver().getALocalSource*() = request and
      (
        deliveryCall.getMethodName() = "then" and
        callback = deliveryCall.getArgument(0).getAFunctionValue() and
        source = callback.getParameter(0)
        or
        deliveryCall.getMethodName() = "end" and
        callback = deliveryCall.getArgument(0).getAFunctionValue() and
        source = callback.getParameter(1)
      )
    )
  }

  predicate isRemoteDataSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call |
      call = DataFlow::globalVarRef("fetch").getACall() or
      isAxiosRequestCall(call) or
      isGotRequestCall(call) or
      isSuperagentRequestCall(call)
      | source = call
    ) or
    isNodeHttpResponseSource(source) or
    isNodeHttpResponseChunkSource(source) or
    isSuperagentResponseSource(source)
  }
}
