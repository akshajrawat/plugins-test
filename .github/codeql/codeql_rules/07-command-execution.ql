/**
 * @name Command Execution
 * @description Detects Joplin or user-controlled data reaching operating-system command execution.
 * @kind path-problem
 * @problem.severity warning
 * @tags security joplin-plugin command-execution
 * @id js/joplin/command-execution
 */
import javascript
import JoplinSources

predicate isKnownNonSensitiveSettingKey(Expr key) {
  exists(string settingName |
    settingName = key.getStringValue() and
    not Joplin::isSensitiveSetting(settingName)
  )
}

predicate isNonSensitiveSettingRead(DataFlow::CallNode call) {
  call = Joplin::settingsGlobalValue() and
  (
    call.getCalleeName() = "globalValue" and
    isKnownNonSensitiveSettingKey(call.getArgument(0).asExpr())
    or
    call.getCalleeName() = "globalValues" and
    exists(ArrayExpr keys |
      keys = call.getArgument(0).asExpr() and
      not exists(Expr key |
        key = keys.getAnElement() and
        not isKnownNonSensitiveSettingKey(key)
      )
    )
  )
}

predicate isWorkspaceEventParameter(DataFlow::Node source) {
  exists(DataFlow::MethodCallNode hook, DataFlow::FunctionNode callback |
    hook.getReceiver().getALocalSource() = Joplin::workspace() and
    hook.getMethodName() in [
      "onNoteSelectionChange", "onNoteContentChange", "onNoteChange", "onResourceChange",
      "onNoteAlarmTrigger", "onSyncComplete"
    ] and
    callback = hook.getArgument(0).getAFunctionValue() and
    source = callback.getParameter(0)
  )
}

predicate isEditorEventParameter(DataFlow::Node source) {
  exists(DataFlow::MethodCallNode hook, DataFlow::FunctionNode callback |
    hook.getReceiver().getALocalSource() = Joplin::editors() and
    hook.getMethodName() in ["onUpdate", "onActivationCheck"] and
    callback = hook.getArgument(1).getAFunctionValue() and
    source = callback.getParameter(0)
  )
}

predicate isRegisteredEditorEventParameter(DataFlow::Node source) {
  exists(
    DataFlow::MethodCallNode registration,
    DataFlow::ObjectLiteralNode callbacks,
    DataFlow::FunctionNode callback
  |
    registration.getReceiver().getALocalSource() = Joplin::editors() and
    registration.getMethodName() = "register" and
    callbacks = registration.getArgument(1).getALocalSource() and
    (
      callback = callbacks.getAPropertyWrite("onActivationCheck").getRhs().getAFunctionValue() or
      callback = callbacks.getAPropertyWrite("onSetup").getRhs().getAFunctionValue()
    ) and
    source = callback.getParameter(0)
  )
}

predicate isDialogResult(DataFlow::Node source) {
  source = Joplin::dialogs().getAMethodCall("open")
}

predicate executesArgumentListAsShell(SystemCommandExecution execution) {
  execution.getOptionsArg()
      .getALocalSource()
      .getAPropertyWrite("shell")
      .getRhs()
      .asExpr()
      .(BooleanLiteral)
      .getBoolValue() = true
  or
  exists(API::Node options |
    options.asSink() = execution.getOptionsArg() and
    options.getMember("shell").asSink().mayHaveBooleanValue(true)
  )
}

predicate hardcodedCommandValue(SystemCommandExecution execution, string value) {
  value = execution.getACommandArgument().getStringValue() or
  value = execution.getACommandArgument().getALocalSource().getStringValue()
}

predicate isCodeInterpreter(SystemCommandExecution execution) {
  exists(string command |
    hardcodedCommandValue(execution, command) and
    command.regexpMatch(
      "(?i)(^|.*[/\\\\])(node(js)?|deno|bun|python([0-9.]*)?|perl|ruby|php|sh|bash|zsh|cmd(\\.exe)?|powershell(\\.exe)?|pwsh(\\.exe)?|osascript)$"
    )
  )
}

predicate isCommandInput(DataFlow::Node sink) {
  exists(SystemCommandExecution execution |
    sink = execution.getACommandArgument()
    or
    sink = execution.getArgumentList() and
    (executesArgumentListAsShell(execution) or isCodeInterpreter(execution))
  )
}

module CommandExecutionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call |
      isNonSensitiveSettingRead(call) and
      source = call
    ) or
    source = Joplin::data().getAMethodCall("get") or
    source = Joplin::data().getAMethodCall("userDataGet") or
    source = Joplin::workspace().getAMethodCall("selectedNote") or
    isWorkspaceEventParameter(source) or
    isEditorEventParameter(source) or
    isRegisteredEditorEventParameter(source) or
    isDialogResult(source) or
    Joplin::isJoplinMessageSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    isCommandInput(sink)
  }
}

module CommandExecFlow = TaintTracking::Global<CommandExecutionConfig>;
import CommandExecFlow::PathGraph

from CommandExecFlow::PathNode source, CommandExecFlow::PathNode sink
where CommandExecFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Command Execution: Joplin or user-controlled data reaches an operating-system command or its argument list. Verify that the command is expected and cannot be manipulated into executing unintended programs or options."
