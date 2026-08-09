/**
 * @name Suspicious Sensitive Key Access
 * @description Flags plugins that read highly sensitive keys (like sync passwords) or query both master credentials and sync cache together.
 * @kind problem
 * @problem.severity warning
 * @tags security joplin-plugin manual-review
 * @id js/joplin/secret-key-access
 */
import javascript
import JoplinSources

predicate settingNameForCall(DataFlow::CallNode call, string settingName) {
  call = Joplin::settingsGlobalValue() and
  exists(Expr argExpr |
    argExpr = call.getArgument(0).asExpr() and
    (
      settingName = argExpr.getStringValue() or
      settingName = argExpr.(ArrayExpr).getAnElement().getStringValue()
    )
  )
}

bindingset[targetSetting]
predicate isSettingAccess(DataFlow::CallNode call, string targetSetting) {
  exists(string settingName |
    settingNameForCall(call, settingName) and
    settingName = targetSetting
  )
}

bindingset[targetPattern]
predicate isSettingAccessMatching(DataFlow::CallNode call, string targetPattern) {
  exists(string settingName |
    settingNameForCall(call, settingName) and
    settingName.regexpMatch(targetPattern)
  )
}

from DataFlow::CallNode call, string reason
where
  // CONDITION 1: Standalone access to sync passwords, tokens, or caches
  (
    isSettingAccessMatching(call, "sync\\..*\\.password") or
    isSettingAccess(call, "api.token") or
    isSettingAccess(call, "encryption.cachedPpk") or
    isSettingAccess(call, "encryption.passwordCache")
  ) and
  reason = "Trying to access a highly sensitive credential."

  or

  // CONDITION 2: Both 'encryption.masterPassword' AND 'syncInfoCache' are queried in this plugin
  (
    (isSettingAccess(call, "encryption.masterPassword") or isSettingAccess(call, "syncInfoCache"))
    and
    exists(DataFlow::CallNode otherCall |
       (isSettingAccess(otherCall, "encryption.masterPassword") and isSettingAccess(call, "syncInfoCache")) or
       (isSettingAccess(otherCall, "syncInfoCache") and isSettingAccess(call, "encryption.masterPassword"))
    )
  ) and
  reason = "Combined access of BOTH masterPassword and syncInfoCache detected in this codebase."

select call, "MANUAL REVIEW REQUIRED: " + reason
