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
    source = DataFlow::globalVarRef("process").getAPropertyRead("env").getAPropertyRead()
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call, DataFlow::Node setHtmlArg, DataFlow::Node concatNode, string remotePattern |
      remotePattern = "(?is).*<(script|iframe|img|link|meta)\\b[^>]*\\b(src|href|content|url)\\s*=\\s*[\"']?\\s*https?://(?!(localhost|0\\.0\\.0\\.0|\\[::1\\]|::1|127\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})([:/?#\\s\"']|$)).*" and
      call.getCalleeName() = "setHtml" and
      (
        call.getReceiver().getALocalSource() = Joplin::panels() or 
        call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs") or
        call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("editors")
      ) and
      setHtmlArg = call.getArgument(1) and
      
      (
        exists(AddExpr add, Expr left |
          concatNode.asExpr() = add and
          sink.asExpr() = add.getRightOperand() and
          left = add.getLeftOperand() and
          left.getStringValue().regexpMatch(remotePattern)
        )
        or
        exists(TemplateLiteral tpl, TemplateElement elem |
          concatNode.asExpr() = tpl and
          sink.asExpr() = tpl.getAChildExpr() and
          elem = tpl.getAnElement() and
          elem.getValue().regexpMatch(remotePattern)
        )
      ) and
      // The concatenated string flows into the setHtml argument
      concatNode = setHtmlArg.getALocalSource()
    )
  }
}

module UrlSmugglingFlow = TaintTracking::Global<UrlSmugglingConfig>;
import UrlSmugglingFlow::PathGraph

from UrlSmugglingFlow::PathNode source, UrlSmugglingFlow::PathNode sink
where UrlSmugglingFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "URL Smuggling: Sensitive Joplin data is being dynamically injected into an external URL attribute (like `<img src=\"https://...\"`) in a Webview. \\n**Reviewer Action:** This can be used to silently exfiltrate sensitive data such as user notes or tokens to an attacker's server without requiring a direct network fetch."
