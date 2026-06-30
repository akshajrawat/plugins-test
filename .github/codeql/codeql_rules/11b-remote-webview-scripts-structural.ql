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

from DataFlow::CallNode call, DataFlow::Node sink
where
  call.getCalleeName() = "setHtml" and
  (call.getReceiver().getALocalSource() = Joplin::panels() or call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs")) and
  sink = call.getArgument(1) and
  hasExternalWebviewSrc(sink)
select call, "Remote Webview Injection: The plugin is dynamically loading an external, remote URL into a Webview (via iframe or script tags) or registering a remote Content Script. \\n**Reviewer Action:** Confirm the URL points to a trusted, known-good domain (like a CDN or official docs). Loading unverified remote scripts allows an attacker to bypass plugin updates and dynamically execute malicious UI code."
