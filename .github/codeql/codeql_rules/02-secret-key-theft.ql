/**
 * ## **2. RULE 2 :** 
 * **The Sinks :** It watches functions that are capable of leaking or exposing data : `fetch`, `axios`, `https.request`, `http.request`, `writeFile`, `writeFileSync`, `appendFile`, `createWriteStream`, `child_process` methods, `joplin.data.put`, `setHtml`, `postMessage`, `net.connect`, `tls.connect` and send (WebSockets)
 * 
 * @name Secret and Key Theft
 * @description Detects sensitive settings flowing out to network, fs, child_process, or webview.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin secret-key-theft
 * @id js/joplin/secret-key-theft
 */
import javascript
import DataFlow::PathGraph
import JoplinSources

bindingset[setting]
predicate isSensitiveSetting(string setting) {
  setting = "syncInfoCache" or
  setting = "encryption.masterPassword" or
  setting = "api.token" or
  setting = "encryption.cachedPpk" or
  setting = "encryption.passwordCache" or
  setting.regexpMatch("sync\\..*\\.password")
}

class SecretTheftConfig extends TaintTracking::Configuration {
  SecretTheftConfig() { this = "SecretTheftConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call, Expr argExpr, string settingName |
      
      (call.getCalleeName() = "globalValue" or call.getCalleeName() = "globalValues") and
      argExpr = call.getArgument(0).asExpr() and
      (
        settingName = argExpr.getStringValue() 
        or 
        settingName = argExpr.(ArrayExpr).getAnElement().getStringValue()
      ) and
      isSensitiveSetting(settingName) |
      source = call
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call | 
      // Network
      call.getCalleeName() = "fetch" or
      call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("axios", _) or
      call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("https", "request") or
      call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("http", "request") or
      call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("net", "connect") or
      call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("tls", "connect") or
      call.getCalleeName() = "send" or
      // File system
      call.getCalleeName() = "writeFile" or
      call.getCalleeName() = "writeFileSync" or
      call.getCalleeName() = "appendFile" or
      call.getCalleeName() = "createWriteStream" or
      // Child process
      call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("child_process", _) or
      // Joplin Notes
      (call.getCalleeName() = "put" and call.getReceiver().getALocalSource() = Joplin::data()) or
      // Webview / External frame
      (call.getCalleeName() = "setHtml" and call.getReceiver().getALocalSource() = Joplin::panels()) or
      (call.getCalleeName() = "postMessage")
    |
      sink = call.getAnArgument()
    )
  }

}

from DataFlow::PathNode source, DataFlow::PathNode sink, SecretTheftConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Sensitive data flowing to critical sink."
