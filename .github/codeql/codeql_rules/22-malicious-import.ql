/**
 * @name Malicious Import Module
 * @description Malicious payloads inside an import module.
 * @kind problem
 * @problem.severity warning
 * @id joplin/malicious-import
 */
import javascript
import JoplinSources

from DataFlow::MethodCallNode reg
where
  reg.getMethodName() = "registerImportModule" and
  exists(DataFlow::PropRead pr |
    pr.getPropertyName() = "interop" and
    reg.getReceiver().getALocalSource() = pr
  )
  or
  // Fallback: any call to registerImportModule on a property named "interop"
  reg.getMethodName() = "registerImportModule" and
  reg.getReceiver().(DataFlow::PropRead).getPropertyName() = "interop"
select reg, "Custom import module registered. Ensure imported data is heavily sanitized."
