/**
 * @name Remote Webview Scripts (Structural)
 * @description Detects creating a webview or content script with dynamic contents that could load remote scripts.
 * @kind problem
 * @problem.severity warning
 * @tags security joplin-plugin remote-webview-structural
 * @id js/joplin/remote-webview-structural
 */
import javascript
import JoplinSources
import JoplinSinks

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

from DataFlow::CallNode call, DataFlow::Node sink
where
  call.getCalleeName() = "setHtml" and
  (call.getReceiver().getALocalSource() = Joplin::panels() or call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs")) and
  sink = call.getArgument(1) and
  hasExternalWebviewSrc(sink)
select call, "Low Confidence: Webview setHtml with external script/iframe src. \n" +
  "Reviewer: verify URL points to known-good domain and not attacker-controlled."
