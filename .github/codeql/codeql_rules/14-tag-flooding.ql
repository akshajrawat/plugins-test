/**
 * @name Asynchronous Tag Flooding & Search Poisoning
 * @description Sabotaging application indexing via programmatic high-volume metadata inflation.
 * @kind problem
 * @problem.severity error
 * @id joplin/tag-flooding
 */
import javascript
import JoplinSources

from DataFlow::CallNode timer, DataFlow::FunctionNode callback, DataFlow::CallNode post
where
  (timer = DataFlow::globalVarRef("setInterval").getACall() or timer = DataFlow::globalVarRef("setTimeout").getACall()) and
  callback = timer.getArgument(0).getALocalSource() and
  post.getContainer() = callback.getFunction() and
  post = Joplin::data().getAMethodCall("post") and
  post.getArgument(0).getALocalSource().(DataFlow::ArrayCreationNode).getElement(0).getStringValue() = "tags"
select post, "Tag Flooding: Asynchronous creation of tags in a background loop."
