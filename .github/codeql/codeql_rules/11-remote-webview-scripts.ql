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

bindingset[value]
predicate containsExternalWebviewSrc(string value) {
  value.regexpMatch("(?is).*<(script|iframe)\\b[^>]*\\bsrc\\s*=\\s*[\"']?\\s*https?://(?!(localhost|0\\.0\\.0\\.0|\\[::1\\]|::1|127\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})([:/?#\\s\"']|$)).*")
}

predicate hasExternalWebviewSrc(DataFlow::Node html) {
  exists(string value |
    (value = html.getStringValue() or value = html.getALocalSource().getStringValue()) and
    containsExternalWebviewSrc(value)
  )
  or
  exists(StringLiteral str |
    html.asExpr().getAChildExpr*() = str and
    containsExternalWebviewSrc(str.getStringValue())
  )
}

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
    exists(string val |
      (source.asExpr() instanceof StringLiteral or source.asExpr() instanceof TemplateLiteral) and
      val = source.getStringValue() and
      containsExternalWebviewSrc(val)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      // setHtml sinks (panels and dialogs)
      call.getCalleeName() = "setHtml" and
      (call.getReceiver().getALocalSource() = Joplin::panels() or call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs")) and
      sink = call.getArgument(1) and
      hasExternalWebviewSrc(sink)
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
