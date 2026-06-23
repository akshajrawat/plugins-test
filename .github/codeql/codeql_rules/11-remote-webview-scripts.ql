/**
 * @name Remote Webview Scripts
 * @description Detects creating a webview or content script with an external remote URL dynamically.
 * @kind path-problem
 * @problem.severity warning
 * @tags security joplin-plugin remote-webview
 * @id js/joplin/remote-webview
 */
import javascript
import JoplinSources
import JoplinSinks
import JoplinLinks

module RemoteWebviewConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // any fetch response
    exists(DataFlow::CallNode call | call.getCalleeName() = "fetch" and source = call) or
    // any axios/http response
    exists(DataFlow::CallNode call | call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("axios", "get") and source = call) or
    // joplin settings
    source = Joplin::settingsGlobalValue() or
    exists(DataFlow::MethodCallNode call | call.getMethodName() = "value" and call.getReceiver().getALocalSource() = Joplin::settings() and source = call) or
    // environment variables
    (source.asExpr() instanceof PropAccess and source.asExpr().(PropAccess).getBase().(GlobalVarAccess).getName() = "process") or
    // hardcoded external URLs
    (source.asExpr() instanceof StringLiteral and source.getStringValue().regexpMatch("(?is).*https?://(?!localhost|127\\.|0\\.0\\.0\\.0|::1).*"))
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      // setHtml sinks (panels and dialogs)
      (
        call.getCalleeName() = "setHtml" and
        (call.getReceiver().getALocalSource() = Joplin::panels() or call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs")) and
        sink = call.getArgument(1) and
        (
          sink.getStringValue().regexpMatch("(?is).*<(script|iframe)[^>]+src=.*") or
          exists(StringLiteral str |
            sink.asExpr().getAChildExpr*() = str and
            str.getStringValue().regexpMatch("(?is).*(<script|<iframe).*")
          )
        )
      )
      or
      // contentScripts.register sink
      (
        call.getCalleeName() = "register" and
        call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("contentScripts") and
        sink = call.getArgument(2)
      )
    )
  }
}

module RemoteWebview = TaintTracking::Global<RemoteWebviewConfig>;
import RemoteWebview::PathGraph

from RemoteWebview::PathNode source, RemoteWebview::PathNode sink
where RemoteWebview::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote external URL loaded into Webview. \n" +
  "Reviewer: verify (1) URL points to attacker-controlled or unexpected domain vs. known-good CDN/docs, \n" +
  "(2) URL is used as a script/iframe src vs. a harmless link or image, \n" +
  "(3) content-script registration elsewhere in the plugin also loads remote code."
