/**
 * @name Network Backdoor
 * @description Detects opening a listening port on the user's local network.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin network-backdoor
 * @id js/joplin/network-backdoor
 */
import javascript

module NetworkBackdoorConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = DataFlow::moduleMember("net", "createServer").getACall() or
    source = DataFlow::moduleMember("node:net", "createServer").getACall() or
    source = DataFlow::moduleMember("http", "createServer").getACall() or
    source = DataFlow::moduleMember("node:http", "createServer").getACall() or
    source = DataFlow::moduleMember("https", "createServer").getACall() or
    source = DataFlow::moduleMember("node:https", "createServer").getACall() or
    source = DataFlow::moduleMember("tls", "createServer").getACall() or
    source = DataFlow::moduleMember("node:tls", "createServer").getACall() or
    source = DataFlow::moduleMember("dgram", "createSocket").getACall() or
    source = DataFlow::moduleMember("node:dgram", "createSocket").getACall() or
    source = DataFlow::moduleMember("ws", "Server").getAnInstantiation() or
    source = DataFlow::moduleMember("ws", "Server").getACall() or
    source = DataFlow::moduleImport("ws").getAPropertyRead("Server").getAnInstantiation() or
    source = DataFlow::moduleImport("socket.io").getAnInstantiation() or
    source = DataFlow::moduleMember("socket.io", "Server").getAnInstantiation() or
    source = DataFlow::moduleImport("express").getACall() or
    source = DataFlow::moduleImport("koa").getACall() or
    source = DataFlow::moduleImport("koa").getAnInstantiation() or
    source = DataFlow::moduleImport("fastify").getACall()
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() in ["listen", "bind", "start"]
    |
      sink = call.getReceiver()
    )
  }
}

predicate isSafeLocalHostBind(DataFlow::MethodCallNode call) {
  exists(DataFlow::Node arg |
    arg = call.getAnArgument() and
    arg.getStringValue().regexpMatch("(?i)^(127\\.0\\.0\\.1|localhost|::1)$")
  )
}

module NetworkBackdoorFlow = TaintTracking::Global<NetworkBackdoorConfig>;
import NetworkBackdoorFlow::PathGraph

from NetworkBackdoorFlow::PathNode source, NetworkBackdoorFlow::PathNode sink, DataFlow::MethodCallNode call, string msg
where 
  NetworkBackdoorFlow::flowPath(source, sink) and
  call.getReceiver() = sink.getNode() and
  call.getMethodName() in ["listen", "bind", "start"] and
  (
    if isSafeLocalHostBind(call)
    then msg = "Localhost Bind Detected: The plugin is opening a local listening port restricted to localhost. \\n**Reviewer Action:** Check if the plugin explicitly advertises running a local server (e.g., a companion web app). While bound locally, ensure it requires explicit authentication if sensitive data can be queried."
    else msg = "[PUBLIC/DYNAMIC BIND DETECTED] Network Backdoor: The plugin is opening a listening port that may be accessible externally (e.g., 0.0.0.0 or unspecified host). \\n**Reviewer Action:** This is a severe threat indicator. An externally accessible listening port exposes the plugin and potentially Joplin to the local network or internet. Verify this is strictly required and heavily authenticated."
  )
select sink.getNode(), source, sink, msg
