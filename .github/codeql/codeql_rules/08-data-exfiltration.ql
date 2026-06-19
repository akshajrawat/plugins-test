/**
 * @name Data Exfiltration
 * @description Detects bulk-reading notes and piping the data to network requests.
 * @kind problem
 * @problem.severity warning
 * @tags security joplin-plugin data-exfiltration
 * @id js/joplin/data-exfiltration
 */
import javascript
import JoplinSources

/**
 * Holds if `call` reads Joplin note data via joplin.data.get() or similar.
 */
predicate readsJoplinData(DataFlow::MethodCallNode call) {
  call.getMethodName() = "get" and
  call.getReceiver().getALocalSource() = Joplin::data()
  or
  call.getMethodName() = "onNoteChange" and
  call.getReceiver().getALocalSource() = Joplin::workspace()
}

/**
 * Holds if `call` sends data over the network via fetch, axios, http, or https.
 */
predicate sendsToNetwork(DataFlow::CallNode call) {
  call.getCalleeName() = "fetch" or
  call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("axios", _) or
  call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("https", "request") or
  call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("http", "request") or
  call.getCalleeName() = "postMessage"
}

from DataFlow::CallNode networkCall, DataFlow::MethodCallNode dataRead, Function enclosingFn
where
  readsJoplinData(dataRead) and
  sendsToNetwork(networkCall) and
  enclosingFn = networkCall.getEnclosingFunction() and
  enclosingFn = dataRead.getEnclosingFunction()
select networkCall, "Data exfiltration: Joplin data read via $@ is sent to a network call in the same function.", dataRead, dataRead.toString()
