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
    source = DataFlow::moduleMember("http", "createServer").getACall() or
    source = DataFlow::moduleMember("https", "createServer").getACall() or
    source = DataFlow::moduleMember("tls", "createServer").getACall() or
    source = DataFlow::moduleMember("dgram", "createSocket").getACall() or
    source = DataFlow::moduleMember("ws", "Server").getAnInstantiation() or
    source = DataFlow::moduleImport("express").getACall() or
    source = DataFlow::moduleImport("koa").getACall() or
    source = DataFlow::moduleImport("koa").getAnInstantiation() or
    source = DataFlow::moduleImport("fastify").getACall()
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() in ["listen", "bind"]
    |
      sink = call.getReceiver()
    )
  }
}

module NetworkBackdoorFlow = TaintTracking::Global<NetworkBackdoorConfig>;
import NetworkBackdoorFlow::PathGraph

from NetworkBackdoorFlow::PathNode source, NetworkBackdoorFlow::PathNode sink
where NetworkBackdoorFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Network Backdoor Detected: The plugin is opening a local listening port (via `net`, `http`, or frameworks like `Express`) to accept incoming connections. \\n**Reviewer Action:** Check if the plugin explicitly advertises running a local server (e.g., a companion web app). If this is undocumented, it acts as a backdoor. Verify that the server binds securely (e.g., localhost only) and requires explicit authentication."
