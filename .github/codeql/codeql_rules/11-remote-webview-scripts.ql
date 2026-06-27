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
  value.regexpMatch("(?is).*<(script|iframe|img)\\b[^>]*\\bsrc\\s*=\\s*[\"']?\\s*https?://(?!(localhost|0\\.0\\.0\\.0|\\[::1\\]|::1|127\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})([:/?#\\s\"']|$)).*")
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



predicate hasSmuggledUrl(DataFlow::Node html) {
  exists(StringLiteral str |
    html.asExpr().getAChildExpr*() = str and
    str.getStringValue().regexpMatch("(?is).*<(img|iframe|script)\\b[^>]*\\bsrc\\s*=\\s*[\"'].*")
  )
}

module UrlSmugglingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode getCall |
      getCall = Joplin::data().getAMethodCall("get") and source = getCall
    ) or
    exists(DataFlow::CallNode call |
      call = Joplin::settingsGlobalValue() and
      Joplin::isSensitiveSetting(call.getArgument(0).getStringValue()) and
      source = call
    ) or
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "value" and
      call.getReceiver().getALocalSource() = Joplin::settings() and
      Joplin::isSensitiveSetting(call.getArgument(0).getStringValue()) and
      source = call
    )
  }
  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "setHtml" and
      (call.getReceiver().getALocalSource() = Joplin::panels() or call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs")) and
      sink = call.getArgument(1) and
      hasSmuggledUrl(sink)
    )
  }
}

module CombinedWebviewConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    RemoteWebviewConfig::isSource(source) or UrlSmugglingConfig::isSource(source)
  }
  predicate isSink(DataFlow::Node sink) {
    RemoteWebviewConfig::isSink(sink) or UrlSmugglingConfig::isSink(sink)
  }
}
module CombinedWebview = TaintTracking::Global<CombinedWebviewConfig>;
import CombinedWebview::PathGraph


from CombinedWebview::PathNode source, CombinedWebview::PathNode sink, DataFlow::Node sourceNode, DataFlow::Node sinkNode, string msg
where 
  CombinedWebview::flowPath(source, sink) and
  sourceNode = source.getNode() and
  sinkNode = sink.getNode() and
  (
    (
      RemoteWebviewConfig::isSource(sourceNode) and
      RemoteWebviewConfig::isSink(sinkNode) and
      msg = "Remote Webview Injection: The plugin is dynamically loading an external, remote URL into a Webview (via iframe or script tags) or registering a remote Content Script. \\n**Reviewer Action:** Confirm the URL points to a trusted, known-good domain (like a CDN or official docs). Loading unverified remote scripts allows an attacker to bypass plugin updates and dynamically execute malicious UI code."
    )
    or
    (
      UrlSmugglingConfig::isSource(sourceNode) and
      UrlSmugglingConfig::isSink(sinkNode) and
      msg = "URL Smuggling: Sensitive data flows into Webview URL/HTML."
    )
  )
select sinkNode, source, sink, msg
