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

bindingset[value]
predicate containsExternalWebviewUrlAttribute(string value) {
  exists(string remoteUrlPattern |
    remoteUrlPattern = "https?://(?!(localhost|0\\.0\\.0\\.0|\\[::1\\]|::1|127\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})([:/?#\\s\"']|$))" |
    value.regexpMatch("(?is).*<(script|iframe|img)\\b[^>]*\\bsrc\\s*=\\s*[\"']?\\s*" + remoteUrlPattern + ".*") or
    value.regexpMatch("(?is).*<link\\b[^>]*\\bhref\\s*=\\s*[\"']?\\s*" + remoteUrlPattern + ".*") or
    value.regexpMatch("(?is).*<meta\\b[^>]*\\bcontent\\s*=\\s*[\"']?[^>]*\\burl\\s*=\\s*" + remoteUrlPattern + ".*")
  )
}

predicate isJoplinSetHtmlCall(DataFlow::CallNode call) {
  call.getCalleeName() = "setHtml" and
  (
    call.getReceiver().getALocalSource() = Joplin::panels() or 
    call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs") or
    call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("editors")
  )
}

bindingset[name]
predicate isSensitiveEnvironmentVariableName(string name) {
  name.regexpMatch("(?i).*(token|secret|key|password|passwd|passphrase|credential|auth|session|cookie|private).*")
}

predicate isSensitiveEnvironmentVariableAccess(DataFlow::Node source) {
  exists(DataFlow::PropRead envRead, string name |
    envRead = DataFlow::globalVarRef("process").getAPropertyRead("env").getAPropertyRead() and
    name = envRead.getPropertyName() and
    isSensitiveEnvironmentVariableName(name) and
    source = envRead
  )
}

predicate externalUrlPrefixBefore(Expr expr) {
  exists(StringLiteral str |
    expr.getAChildExpr*() = str and
    containsExternalWebviewUrlAttribute(str.getStringValue())
  )
}

predicate htmlRootExpr(DataFlow::Node html, Expr root) {
  root = html.asExpr() or
  root = html.getALocalSource().asExpr()
}

predicate isDynamicExternalUrlPart(DataFlow::Node html, DataFlow::Node sink) {
  exists(Expr root, AddExpr add |
    htmlRootExpr(html, root) and
    add = root.getAChildExpr*() and
    sink.asExpr() = add.getRightOperand() and
    externalUrlPrefixBefore(add.getLeftOperand())
  )
  or
  exists(Expr root, TemplateLiteral tpl, TemplateElement elem |
    htmlRootExpr(html, root) and
    tpl = root.getAChildExpr*() and
    sink.asExpr() = tpl.getAChildExpr() and
    elem = tpl.getAnElement() and
    containsExternalWebviewUrlAttribute(elem.getValue())
  )
}

module UrlSmugglingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Joplin data
    exists(DataFlow::CallNode getCall |
      getCall = Joplin::data().getAMethodCall("get") and source = getCall
    ) or
    // Sensitive global setting
    exists(DataFlow::CallNode call |
      call = Joplin::settingsGlobalValue() and
      Joplin::isSensitiveSetting(call.getArgument(0).getStringValue()) and
      source = call
    ) or
    // Environment variables
    isSensitiveEnvironmentVariableAccess(source)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call, DataFlow::Node setHtmlArg |
      isJoplinSetHtmlCall(call) and
      setHtmlArg = call.getArgument(1) and
      isDynamicExternalUrlPart(setHtmlArg, sink)
    )
  }
}

module UrlSmugglingFlow = TaintTracking::Global<UrlSmugglingConfig>;
import UrlSmugglingFlow::PathGraph

from UrlSmugglingFlow::PathNode source, UrlSmugglingFlow::PathNode sink
where UrlSmugglingFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "URL Smuggling: Sensitive Joplin data is being dynamically injected into an external URL attribute (like `<img src=\"https://...\"`) in a Webview. This can be used to silently exfiltrate sensitive data such as user notes or tokens to an attacker's server without requiring a direct network fetch."
