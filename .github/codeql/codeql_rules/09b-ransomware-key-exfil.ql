/**
 * @name Ransomware Key Exfiltration
 * @description Detects encryption key material being sent to a network endpoint.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin ransomware-key-exfil
 * @id js/joplin/ransomware-key-exfil
 */
import javascript
import JoplinSources
import JoplinSinks

predicate isKeyMaterialUse(DataFlow::Node key) {
  exists(DataFlow::CallNode call |
    call.getCalleeName() in ["createCipher", "createCipheriv"] and
    key = call.getArgument(1)
  ) or
  exists(DataFlow::MethodCallNode call |
    call.getMethodName() = "encrypt" and
    key = call.getArgument(1)
  ) or
  exists(DataFlow::MethodCallNode call |
    call.getMethodName() = "importKey" and
    (
      key = call.getArgument(1) or
      key = call.getArgument(2)
    )
  )
}

predicate isKeyMaterialSource(DataFlow::Node key) {
  exists(DataFlow::Node keyUse |
    isKeyMaterialUse(keyUse) and
    (
      key = keyUse or
      key = keyUse.getALocalSource()
    )
  )
}

module RansomwareKeyExfilConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isKeyMaterialSource(source)
  }
  predicate isSink(DataFlow::Node sink) {
    isNetworkExfiltrationSink(sink)
  }
}
module RansomwareKeyExfil = TaintTracking::Global<RansomwareKeyExfilConfig>;
import RansomwareKeyExfil::PathGraph

from RansomwareKeyExfil::PathNode source, RansomwareKeyExfil::PathNode sink
where RansomwareKeyExfil::flowPath(source, sink)
select sink.getNode(), source, sink, "Critical Ransomware Indicator: Encryption key material is flowing to an external network endpoint."
