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

from DataFlow::CallNode call, DataFlow::Node sink
where
  (
    call.getCalleeName() = "setHtml" and
    (call.getReceiver().getALocalSource() = Joplin::panels() or call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs")) and
    sink = call.getArgument(1) and
    (
      sink.getStringValue().regexpMatch("(?is).*<(script|iframe)[^>]+src=.*") or
      sink.getStringValue().regexpMatch("(?is).*(<script|<iframe).*")
    )
  )
  or
  (
    call.getCalleeName() = "register" and
    call.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("contentScripts") and
    sink = call.getArgument(2)
  )
select call, "Low Confidence: Webview setHtml with script/iframe, or contentScripts.register used. \n" +
  "Reviewer: verify URL points to known-good domain and not attacker-controlled."
