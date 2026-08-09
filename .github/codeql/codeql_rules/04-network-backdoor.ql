/**
 * @name Network Backdoor
 * @description Detects opening a listening port on the user's local network.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin network-backdoor
 * @id js/joplin/network-backdoor
 */
import javascript

predicate isWebSocketServerCreation(DataFlow::InvokeNode server) {
  server = DataFlow::moduleMember("ws", "Server").getAnInstantiation() or
  server = DataFlow::moduleMember("ws", "Server").getACall() or
  server = DataFlow::moduleMember("ws", "WebSocketServer").getAnInstantiation() or
  server = DataFlow::moduleMember("ws", "WebSocketServer").getACall() or
  server = DataFlow::moduleImport("ws").getAPropertyRead("Server").getAnInstantiation() or
  server = DataFlow::moduleImport("ws").getAPropertyRead("WebSocketServer").getAnInstantiation()
}

predicate isSocketIoServerCreation(DataFlow::InvokeNode server) {
  server = DataFlow::moduleImport("socket.io").getAnInstantiation() or
  server = DataFlow::moduleMember("socket.io", "Server").getAnInstantiation()
}

predicate hasOption(DataFlow::InvokeNode call, string propertyName) {
  exists(DataFlow::Node value |
    value = call.getAnArgument().getALocalSource().getAPropertyWrite(propertyName).getRhs()
  )
}

predicate isConstructorListeningServer(DataFlow::InvokeNode server) {
  (
    isWebSocketServerCreation(server) and
    hasOption(server, "port")
  ) or
  (
    isSocketIoServerCreation(server) and
    server.getArgument(0).asExpr() instanceof NumberLiteral
  )
}

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
    isWebSocketServerCreation(source.(DataFlow::InvokeNode)) or
    isSocketIoServerCreation(source.(DataFlow::InvokeNode)) or
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
    ) or
    isConstructorListeningServer(sink.(DataFlow::InvokeNode))
  }
}

predicate isLoopbackHost(DataFlow::Node host) {
  host.getStringValue().regexpMatch("(?i)^(127\\.0\\.0\\.1|localhost|::1)$")
}

predicate isSafeLocalHostBind(DataFlow::InvokeNode call) {
  exists(DataFlow::Node arg |
    arg = call.getAnArgument() and
    isLoopbackHost(arg)
  ) or
  exists(DataFlow::Node host |
    (
      host = call.getAnArgument().getALocalSource().getAPropertyWrite("host").getRhs() or
      host = call.getAnArgument().getALocalSource().getAPropertyWrite("address").getRhs()
    ) and
    isLoopbackHost(host)
  )
}

predicate isListeningOperationForSink(DataFlow::InvokeNode operation, DataFlow::Node sink) {
  exists(DataFlow::MethodCallNode call |
    operation = call and
    call.getMethodName() in ["listen", "bind", "start"] and
    sink = call.getReceiver()
  ) or
  (
    operation = sink.(DataFlow::InvokeNode) and
    isConstructorListeningServer(operation)
  )
}

module NetworkBackdoorFlow = TaintTracking::Global<NetworkBackdoorConfig>;
import NetworkBackdoorFlow::PathGraph

from NetworkBackdoorFlow::PathNode source, NetworkBackdoorFlow::PathNode sink, DataFlow::InvokeNode operation, string msg
where 
  NetworkBackdoorFlow::flowPath(source, sink) and
  isListeningOperationForSink(operation, sink.getNode()) and
  (
    if isSafeLocalHostBind(operation)
    then msg = "Localhost Bind Detected: The plugin is opening a local listening port restricted to localhost. Check if the plugin explicitly advertises running a local server."
    else msg = "Network Backdoor: The plugin is opening a listening port that may be accessible externally. This is a severe threat indicator. Verify whether this is strictly required and heavily authenticated."
  )
select sink.getNode(), source, sink, msg
