/**
 * ## **4. RULE 4 :**
 * **The Sources :** It flags the initialization of various server and socket types: `net.createServer()`, `http.createServer()`, `https.createServer()`, `dgram.createSocket()` (for UDP), `ws.Server()` (for WebSockets), and server framework instances like `express()` or `koa()`, `tls.createServer()`, `fastify()` 
 * 
 * **The Sinks :** It watches methods that bind these servers to the local network: `.listen()` (the standard for TCP/HTTP) and `.bind()` (the standard for UDP), `.start()`
 * 
 * @name Network Backdoor
 * @description Detects opening a listening port on the user's local network.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin network-backdoor
 * @id js/joplin/network-backdoor
 */
import javascript
import DataFlow::PathGraph

class NetworkBackdoorConfig extends TaintTracking::Configuration {
  NetworkBackdoorConfig() { this = "NetworkBackdoorConfig" }

  override predicate isSource(DataFlow::Node source) {
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

  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() in ["listen", "bind", "start"]
    |
      sink = call.getReceiver()
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, NetworkBackdoorConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Network backdoor detected: opening a listening port."
