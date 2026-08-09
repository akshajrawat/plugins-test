/**
 * @name Remote Webview Scripts (Structural)
 * @description Detects Joplin webview HTML that directly loads external remote resources.
 * @kind problem
 * @problem.severity warning
 * @tags security joplin-plugin remote-webview-structural
 * @id js/joplin/remote-webview-structural
 */
import javascript
import JoplinSources

bindingset[value]
predicate containsExternalWebviewSrc(string value) {
  exists(string remoteUrlPattern |
    remoteUrlPattern = "https?://(?!(localhost|0\\.0\\.0\\.0|\\[::1\\]|::1|127\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})([:/?#\\s\"']|$))" |
    value.regexpMatch("(?is).*<(script|iframe)\\b[^>]*\\bsrc\\s*=\\s*[\"']?\\s*" + remoteUrlPattern + ".*") or
    value.regexpMatch("(?is).*<link\\b[^>]*\\bhref\\s*=\\s*[\"']?\\s*" + remoteUrlPattern + ".*") or
    value.regexpMatch("(?is).*<meta\\b[^>]*\\bhttp-equiv\\s*=\\s*[\"']?refresh[\"']?[^>]*\\bcontent\\s*=\\s*[\"']?\\s*[0-9]+(\\.[0-9]+)?\\s*;\\s*url\\s*=\\s*" + remoteUrlPattern + ".*") or
    value.regexpMatch("(?is).*<meta\\b[^>]*\\bcontent\\s*=\\s*[\"']?\\s*[0-9]+(\\.[0-9]+)?\\s*;\\s*url\\s*=\\s*" + remoteUrlPattern + "[^>]*\\bhttp-equiv\\s*=\\s*[\"']?refresh[\"']?.*") or
    value.regexpMatch("(?is).*\\burl\\s*\\(\\s*[\"']?\\s*" + remoteUrlPattern + ".*\\).*")
  )
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
  or
  exists(TemplateElement element |
    html.asExpr().getAChildExpr*() = element and
    containsExternalWebviewSrc(element.getValue())
  )
}

from DataFlow::CallNode call, DataFlow::Node sink
where
  call.getCalleeName() = "setHtml" and
  (
    call.getReceiver().getALocalSource() = Joplin::panels() or 
    call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs") or
    call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("editors")
  ) and
  sink = call.getArgument(1) and
  hasExternalWebviewSrc(sink)
select call, "Remote Webview Resource: The plugin directly embeds an external URL in a Webview (via iframe, script, link, meta refresh, or CSS). Confirm the URL points to a trusted, known-good domain."
