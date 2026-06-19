/**
 * @name Resource Exhaustion & Storage DoS
 * @description Saturating local device disks or cloud sync storage quotas by generating large, hidden payloads.
 * @kind problem
 * @problem.severity error
 * @id joplin/resource-exhaustion
 */
import javascript
import JoplinSources

from DataFlow::CallNode timer, DataFlow::FunctionNode callback, DataFlow::CallNode post
where
  (timer = DataFlow::globalVarRef("setInterval").getACall() or timer = DataFlow::globalVarRef("setTimeout").getACall()) and
  callback = timer.getArgument(0).getALocalSource() and
  post.getContainer() = callback.getFunction() and
  post = Joplin::data().getAMethodCall("post") and
  post.getArgument(0).getALocalSource().(DataFlow::ArrayCreationNode).getElement(0).getStringValue() = "resources"
select post, "Resource Exhaustion: Asynchronous generation of resources in a background loop."
