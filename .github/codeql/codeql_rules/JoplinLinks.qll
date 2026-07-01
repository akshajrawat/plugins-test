import javascript

class JoplinSharedTaintSteps extends TaintTracking::SharedTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    
    // Response parsing: .text(), .json(), .blob()
    exists(DataFlow::MethodCallNode mc |
      (mc.getMethodName() = "text" or mc.getMethodName() = "json" or mc.getMethodName() = "blob") and
      pred = mc.getReceiver() and succ = mc
    )
    or
    // Object property read: .data, .body
    exists(DataFlow::PropRead pr |
      (pr.getPropertyName() = "data" or pr.getPropertyName() = "body") and
      pred = pr.getBase() and succ = pr
    )
    or
    // JSON parse/stringify
    exists(DataFlow::CallNode call |
      (call = DataFlow::globalVarRef("JSON").getAMemberCall("stringify") or
       call = DataFlow::globalVarRef("JSON").getAMemberCall("parse")) and
      pred = call.getAnArgument() and succ = call
    )
    or
    // Object Literal definition: flow from property value to object
    exists(DataFlow::ObjectLiteralNode obj |
      pred = obj.getAPropertyWrite().getRhs() and
      succ = obj
    )
    or
    // map.set(key, x)
    exists(DataFlow::MethodCallNode mc |
      mc.getMethodName() = "set" and pred = mc.getArgument(1) and succ = mc.getReceiver()
    )
    or
    // map.get(key)
    exists(DataFlow::MethodCallNode mc |
      mc.getMethodName() = "get" and pred = mc.getReceiver() and succ = mc
    )
    or
    // set.add(x)
    exists(DataFlow::MethodCallNode mc |
      mc.getMethodName() = "add" and pred = mc.getArgument(0) and succ = mc.getReceiver()
    )
    or
    // REMOVED: a step from "receiver tainted" -> "callback param tainted"
    // does not model how registration-style callbacks actually receive
    // tainted data. The callback parameter is tainted by data delivered
    // at INVOCATION time (e.g. when an event fires), not by the object
    // the callback was registered on. This requires a per-API isSource
    // declaration in the relevant threat rule (e.g. "parameter 0 of any
    // callback passed to onNoteContentChange is a source"), not a shared
    // step. Tracked separately — out of scope for this file.

    // obj[dynamicKey] - if the BASE object is tainted, a dynamic/computed
    // read result is tainted too (static analysis can't resolve which key,
    // so we over-approximate from the base, not the key expression)
    exists(DataFlow::PropRead pr |
      not exists(pr.getPropertyName()) and
      pred = pr.getBase() and
      succ = pr
    )
    // Obscure npm packages propagation rule removed to reduce false positives
    or
    // zlib.gunzip / inflate callback
    exists(DataFlow::CallNode call |
      (call.getCalleeName() = "gunzip" or call.getCalleeName() = "inflate") and
      pred = call.getArgument(0) and
      succ = call.getLastArgument().getALocalSource().(DataFlow::FunctionNode).getParameter(1)
    )
    or
    // crypto.createCipheriv().update(x)
    exists(DataFlow::MethodCallNode updateCall |
      updateCall.getMethodName() = "update" and
      pred = updateCall.getArgument(0) and succ = updateCall.getReceiver()
    )
    or
    // crypto.createCipheriv().update(x).final() — completes the chain.
    // Without this, taint reaches the cipher receiver via .update() but
    // never reaches .final()'s output, so the full exfil pattern is missed.
    exists(DataFlow::MethodCallNode finalCall |
      finalCall.getMethodName() = "final" and
      pred = finalCall.getReceiver() and succ = finalCall
    )
    or
    // crypto.pbkdf2 callback
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "pbkdf2" and
      pred = call.getArgument(0) and
      succ = call.getLastArgument().getALocalSource().(DataFlow::FunctionNode).getParameter(1)
    )
    or
    // fs.readFile callback
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "readFile" and
      pred = call.getArgument(0) and
      succ = call.getLastArgument().getALocalSource().(DataFlow::FunctionNode).getParameter(1)
    )
  }
}

/**
 * Transfers taint from a file payload to the file path variable itself,
 * enabling detection of drop-and-execute attack chains.
 */
class FileWriteTaintStep extends TaintTracking::SharedTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    exists(FileSystemWriteAccess acc |
      pred = acc.getADataNode() and
      succ = acc.getAPathArgument()
    )
  }
}
