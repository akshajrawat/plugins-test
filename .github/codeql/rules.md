# Rule 1 : Dynamic Code Execution
Detects remote, message, or persisted user-data payloads that reach JavaScript execution APIs.
This rule is focused on code strings that can be evaluated at runtime.

### Flows :
1. Remote request results from `fetch`, `axios`, `http`, `https`, `got`, or `superagent` flow into execution sinks.
2. Message event callback data from windows, HTTP streams, WebSockets, workers, or Joplin webview messages flows into execution sinks.
3. `joplin.data.userDataGet()` payloads flow into execution sinks.
4. Execution sinks include `eval`, `Function`, string-based `setTimeout`, string-based `setInterval`, and `vm` execution APIs.

### Messages :
1. Remote data flows to dynamic code execution. Verify if the endpoint is a trusted Joplin service or a remote server.

### SEVERITY : ERROR

# Rule 2 : Secret and Key Theft
Detects sensitive Joplin settings that flow into external or untrusted sinks.
It covers credential, sync, encryption, API token, client ID, and user identity settings.

### Flows :
1. `joplin.settings.globalValue()` or `globalValues()` for sensitive keys flows into network request data or URLs.
2. Sensitive settings flow into file paths or file contents being written.
3. Sensitive settings flow into command execution sinks.
4. Sensitive settings flow into Joplin data writes, hidden user data, or webview HTML sinks.

### Messages :
1. Critical Security Alert: Sensitive configuration data (such as a master password, sync cache, encryption keys, or API tokens) is flowing directly to an external or untrusted sink. This is highly suspicious behavior. Confirm whether the plugin has a legitimate, fully disclosed reason to touch credentials.

### SEVERITY : ERROR

# Rule 2b : Suspicious Sensitive Key Access
Detects direct reads of highly sensitive settings even when no exfiltration flow is proven.
It is a manual-review signal for suspicious credential access patterns.

### Flows :
1. Code reads `sync.*.password`, `api.token`, `encryption.cachedPpk`, or `encryption.passwordCache`.
2. Code reads both `encryption.masterPassword` and `syncInfoCache` in the same codebase.

### Messages :
1. MANUAL REVIEW REQUIRED: Trying to access a highly sensitive credential.
2. MANUAL REVIEW REQUIRED: Combined access of BOTH masterPassword and syncInfoCache detected in this codebase.

### SEVERITY : WARNING

# Rule 3 : Unauthorized FS Access
Detects ordinary filesystem operations that use path sources outside the plugin data directory.
Archive extraction destinations are handled exclusively by Rule 17b.

### Flows :
1. `__dirname`, `process.cwd()`, Electron app paths, `os.homedir()`, or `os.tmpdir()` flows into filesystem path sinks.
2. Native filesystem and `fs-extra` path arguments are treated as sinks for writes, moves, copies, deletes, renames, chmods, and directory operations.
3. Paths based only on `joplin.plugins.dataDir()` remain safe, while paths mixed with unsafe sources or explicit parent-directory traversal are reported.

### Messages :
1. Temporary Directory Access: The plugin is writing to `os.tmpdir()`. Check if this is a temporary file creation. If it is used for persistent writes, move it to `joplin.plugins.dataDir()`.
2. Unauthorized File System Access: The plugin is using path-revealing variables (like `__dirname` or `process.cwd`) to write, modify, or delete files outside of the safe Joplin sandbox. Plugins must exclusively use `joplin.plugins.dataDir()` for persistent file storage.

### SEVERITY : ERROR

# Rule 3b : Plugin Self-Modification
Detects plugins that attempt to modify their own installed package files.
It distinguishes a path being changed from a path that is only read or mentioned as file content.

### Flows :
1. `__filename` flows into a filesystem mutation target.
2. `joplin.plugins.installationDir()` and a protected package filename (`index.js`, `main.js`, `plugin.js`, `manifest.json`, or `package.json`) flow into the same mutation target.
3. Files that are only copied from the installation directory are not treated as modified, and archive destinations are handled by Rule 17b.

### Messages :
1. Plugin Self-Modification: The plugin is attempting to overwrite or delete its own installation files. A plugin should never modify its own packaged files.

### SEVERITY : ERROR

# Rule 3c : Hardcoded Config Targeting
Detects hardcoded filesystem operations against sensitive local configuration paths.
It flags reads and mutations of Joplin profile files and SSH credential locations.

### Flows :
1. A hardcoded `.config/joplin-desktop` path flows into a filesystem read or mutation target, including its `database.sqlite` file.
2. A hardcoded `.ssh` path or complete `id_rsa` or `authorized_keys` filename flows into a filesystem read or mutation target.
3. Similar-looking filenames, unrelated `database.sqlite` files, and sensitive text used only as file content are not reported.
4. Archive extraction destinations are handled exclusively by Rule 17b.

### Messages :
1. Sensitive Path Targeting: The plugin contains a hardcoded operation targeting a sensitive user configuration or credential path. This is a severe threat indicator for data theft or tampering. Verify this immediately.

### SEVERITY : ERROR

# Rule 4 : Network Backdoor
Detects code that creates a server or socket and starts listening for inbound connections.
It covers Node networking modules and common web server frameworks.

### Flows :
1. `net`, `http`, `https`, `tls`, or `dgram` server/socket creation flows into `listen`, `bind`, or `start`.
2. `ws` or `socket.io` server creation flows into `listen`, `bind`, or `start`.
3. `express`, `koa`, or `fastify` app creation flows into `listen`, `bind`, or `start`.
4. WebSocket servers with a constructor `port` and Socket.IO servers with a numeric constructor port are detected without requiring a later `listen()` call.
5. Positional and option-object `host` or `address` values recognize `localhost`, `127.0.0.1`, and `::1` as loopback-only binds.
6. Localhost-only binds are still reported with a dedicated manual-review message; server objects that never begin listening are not reported.

### Messages :
1. Localhost Bind Detected: The plugin is opening a local listening port restricted to localhost. Check if the plugin explicitly advertises running a local server.
2. Network Backdoor: The plugin is opening a listening port that may be accessible externally. This is a severe threat indicator. Verify whether this is strictly required and heavily authenticated.

### SEVERITY : ERROR

# Rule 5 : Clipboard Injection
Detects data being written back into the user's clipboard from risky sources.
It covers text, HTML, and image replacement using either remote data or existing clipboard content.

### Flows :
1. `joplin.clipboard.readText()`, `readHtml()`, or `readImage()` flows into a clipboard write operation.
2. Remote request results flow into `writeText()`, `writeHtml()`, `writeImage()`, or `write()`.

### Messages :
1. Clipboard Hijacking Risk: The plugin is writing remote data or existing clipboard content back to the user's clipboard. Verify that this is triggered by a deliberate user action (like clicking a "Copy" button). If this happens silently in the background, it may be attempting to replace copied content.

### SEVERITY : ERROR

# Rule 5b : Clipboard Exfiltration
Detects text, HTML, or image clipboard contents being sent over the network.
It tracks reads from Joplin's clipboard API to outbound request sinks.

### Flows :
1. `joplin.clipboard.readText()`, `readHtml()`, or `readImage()` flows into network request data.
2. `joplin.clipboard.readText()`, `readHtml()`, or `readImage()` flows into network request URLs.

### Messages :
1. Clipboard Exfiltration Risk: The plugin is reading the user's clipboard and sending the contents over the network.

### SEVERITY : ERROR

# Rule 5c : Clipboard Execution
Detects text or HTML clipboard contents being executed as code or commands.
It tracks clipboard reads into JavaScript execution and terminal execution sinks.

### Flows :
1. `joplin.clipboard.readText()` or `readHtml()` flows into child process or system command execution.
2. Clipboard text or HTML flows into the global `eval`, `Function`, string-based `setTimeout`, or string-based `setInterval` APIs.
3. Clipboard text or HTML flows into Node `vm` execution APIs such as `runInThisContext`, `runInNewContext`, `runInContext`, `compileFunction`, or `Script`.

### Messages :
1. Clipboard Execution Risk: The plugin is reading the user's clipboard and passing its contents into a code evaluation or terminal command sink.

### SEVERITY : ERROR

# Rule 5d : Clipboard Hijacking (Background)
Detects repeated or background clipboard access.
It is a structural rule for clipboard reads or writes inside loops, iteration callbacks, and recurring timers.

### Flows :
1. `readText()`, `readHtml()`, `readImage()`, `writeText()`, `writeHtml()`, `writeImage()`, or `write()` appears inside a loop.
2. Clipboard access appears inside a `setInterval` callback.
3. Clipboard access appears inside a directly or wrapper-recursive `setTimeout` callback.
4. Clipboard access appears inside `forEach` or `map` callbacks.
5. Clipboard access in helpers called by those repeated callbacks is included; nested helpers that are only declared and never invoked are excluded.

### Messages :
1. Repeated Clipboard Access: The plugin is reading or writing the clipboard inside a loop, iteration callback, or recurring timer. Verify that this repeated access is explicitly initiated and expected by the user.

### SEVERITY : ERROR

# Rule 6 : Native Binary Dropping & Cryptojacking
Detects remote payloads or cryptocurrency-mining indicators reaching operating-system command execution.
It covers both direct command construction and a downloaded payload that is written to a file and then executed.

### Flows :
1. Results from the shared `fetch`, Axios, Got, Superagent, and Node HTTP response model flow into an executable command or its argument list.
2. Downloaded data written to a file taints that file path, so executing the resulting file is detected.
3. Strings containing miner indicators such as `xmrig`, `minerd`, `ethminer`, `cgminer`, `t-rex`, `nsfminer`, `pool.`, `stratum+tcp`, or `nicehash` flow into a command or its argument list.
4. Shell-interpreted inputs, including `exec()` and `spawn()` with `shell: true`, receive a stronger warning.
5. Remote or miner-related values used only as unrelated options or ordinary data are not treated as executable command input.

### Messages :
1. The plugin is passing remote data or a cryptocurrency-mining indicator to a shell-interpreted command. Shell interpretation can treat metacharacters as additional commands. Verify the command input for malware or resource hijacking.
2. The plugin is passing remote data or a cryptocurrency-mining indicator to an operating-system command or its argument list. Verify that it is not executing a downloaded payload or hijacking system resources.

### SEVERITY : ERROR

# Rule 7 : Command Execution
Detects Joplin-controlled or user-controlled data reaching terminal command execution.
It excludes sensitive settings handled by the dedicated secret theft rule.

### Flows :
1. Statically known non-sensitive `joplin.settings.globalValue()` or `globalValues()` results flow into command execution; mixed or sensitive key reads remain owned by Rule 2.
2. `joplin.data.get()`, `joplin.data.userDataGet()`, or `joplin.workspace.selectedNote()` flows into command execution.
3. Parameters from supported workspace and editor lifecycle callbacks flow into command execution.
4. Panel, editor, or content-script messages and user-entered results returned by `joplin.views.dialogs.open()` flow into command execution.
5. Joplin or user-controlled executable values are always reported. Argument lists are reported only when a shell interprets them or a fixed code interpreter such as Node, Python, a system shell, or PowerShell receives them.
6. Ordinary file paths passed as separate arguments to fixed non-shell utilities such as `execFile("cp", ...)` or `execFile("mv", ...)` are not command-execution findings.

### Messages :
1. Command Execution: Joplin or user-controlled data reaches an operating-system command or its argument list. Verify that the command is expected and cannot be manipulated into executing unintended programs or options.

### SEVERITY : WARNING

# Rule 7b : Command Execution (Structural)
Detects hardcoded command strings passed to operating-system command APIs.
It is a structural command-execution indicator that does not require a taint source.

### Flows :
1. A string literal, constant concatenation, or locally assigned constant is used as an executable or shell command.
2. Node child-process APIs and other command APIs represented by CodeQL's `SystemCommandExecution` model, including Execa, are covered.
3. Fixed `cp` and `mv` executions are excluded only when they use a non-shell API. Shell-interpreted forms remain reportable.
4. An execution containing a hardcoded miner indicator in either its command or literal argument list is excluded because Rule 6 owns that finding.
5. Dynamic commands and hardcoded strings used only as ordinary data are not reported by this structural rule.

### Messages :
1. Terminal Command Execution (Hardcoded): A hardcoded operating-system command is executed. Review the command and its arguments to confirm that invoking native processes is required and safe.

### SEVERITY : WARNING

# Rule 8 : Data Exfiltration
Detects note, folder, or resource data being sent to external network endpoints.
It covers bulk Joplin data reads and the currently selected note.

### Flows :
1. `joplin.data.get(["notes", ...])` flows into network request data or URLs.
2. `joplin.data.get(["folders", ...])` flows into network request data or URLs.
3. `joplin.data.get(["resources", ...])` flows into network request data or URLs.
4. Search results and notes returned through a tag's linked `notes` route flow into network request data or URLs.
5. `joplin.workspace.selectedNote()` flows into non-loopback network request data or URLs.
6. Only exact loopback hosts (`localhost`, `127.0.0.1`, and `[::1]`) are excluded.

### Messages :
1. Data Exfiltration Warning: The plugin is reading notes, folders, or resources and sending that data to an external network endpoint. Check if the plugin is a legitimate sync/export tool. If not, this is a massive privacy breach. Verify exactly what data is being sent in the payload.

### SEVERITY : WARNING

# Rule 9 : Mass Encryption / Ransomware
Detects note data being encrypted and written back over the original note.
It models a multi-stage ransomware pattern rather than a single sink.

### Flows :
1. Joplin note data from `joplin.data.get(["notes", ...])` or `selectedNote()` flows into a cipher `update()` or an `encrypt()` call.
2. Encryption output flows specifically into the `body` written by `joplin.data.put(["notes", id], ...)`.
3. The ID read from Joplin must match or flow into the exact write ID, including IDs derived from bulk note reads.
4. Writes executed repeatedly through loops, iteration callbacks, timers, or their helper functions are marked as bulk activity.

### Messages :
1. Ransomware Pattern Detected: The plugin is reading Joplin notes, passing them through an encryption cipher, and overwriting the original notes. Unless this plugin is explicitly designed as an end-to-end encryption tool, this behavior mimics ransomware. Verify that the user holds the decryption keys locally and that this action is the actual behavior of plugin.
2. Ransomware Pattern Detected [BULK LOOP DETECTED]: The plugin is reading Joplin notes, passing them through an encryption cipher, and overwriting the original notes. Unless this plugin is explicitly designed as an end-to-end encryption tool, this behavior mimics ransomware. Verify that the user holds the decryption keys locally and that this action is the actual behavior of plugin.

### SEVERITY : WARNING

# Rule 9b : Ransomware Key Exfiltration
Detects encryption key material being sent over the network.
It focuses on keys used for local encryption operations.

### Flows :
1. Key arguments to `createCipher()` or `createCipheriv()` flow into network request data or URLs.
2. Key arguments to WebCrypto or CryptoJS `encrypt()` operations flow into network request data or URLs.
3. The key-data argument to WebCrypto `importKey()` flows into network request data or URLs; its algorithm metadata is not treated as key material.
4. Key bytes returned by WebCrypto `exportKey()` flow into network request data or URLs.

### Messages :
1. Critical Ransomware Indicator: Encryption key material is flowing to an external network endpoint.

### SEVERITY : ERROR

# Rule 10 : Silent Backup Hijacking (Taint)
Detects export module data flowing into destinations outside the normal export path.
It tracks data from registered Joplin export callbacks to dangerous sinks.

### Flows :
1. `registerExportModule()` callback parameters from `onInit` or `onClose` flow into network, command, or unauthorized filesystem sinks.
2. All `onProcessItem` callback parameters flow into network, command, or unauthorized filesystem sinks.
3. `onProcessResource` callback parameters flow into network, command, or unauthorized filesystem sinks.
4. Inline objects, factory-returned objects, and class instances registered as export modules are covered.
5. File writes and copies under the export destination are excluded, but parent traversal, `dirname()`, and absolute `resolve()` destinations remain reportable.
6. Filesystem access through the official `joplin.require("fs-extra")` API is covered.

### Messages :
1. [High Confidence] Backup Hijacking Alert: Export data is confirmed flowing into a network request, terminal command, or unauthorized file path instead of the legitimate export destination.

### SEVERITY : ERROR

# Rule 10b : Silent Backup Hijacking (Structural)
Detects dangerous operations inside export module callbacks without requiring proven taint flow.
It is a lower-confidence structural companion to Rule 10.

### Flows :
1. A network request executes directly or through a helper from `onInit`, `onProcessItem`, `onProcessResource`, or `onClose`.
2. A command execution sink executes directly or through a helper from one of those export callbacks.
3. A filesystem operation targets a path outside the allowed export destination; copy, move, and rename operations check their destination argument.
4. Inline objects, factory-returned objects, class instances, and `joplin.require("fs-extra")` filesystem calls are covered.
5. The structural result does not require proven export-data flow and may accompany Rule 10's high-confidence result.

### Messages :
1. [Structural Review] Backup Hijacking Indicator: A network request, terminal command, or filesystem operation executes from a Joplin export callback. This structural result does not by itself prove that export data leaves the approved destination. \n**Reviewer Action:** Verify that the operation is required by the export format and that filesystem targets remain under `context.destPath`.

### SEVERITY : WARNING

# Rule 11 : Remote Webview Scripts
Detects sensitive data being injected into external URLs inside Joplin webview HTML.
It covers URL-based exfiltration through dynamic HTML attributes.

### Flows :
1. `joplin.data.get()` results flow into externally hosted `script`, `iframe`, `img`, `link`, or `meta` URL attributes passed to `setHtml()`.
2. Sensitive `joplin.settings.globalValue()` results flow into externally hosted URL attributes passed to `setHtml()`.
3. Sensitive `process.env` values flow into externally hosted URL attributes passed to `setHtml()`.
4. Panel, dialog, and editor `setHtml()` calls are covered.

### Messages :
1. URL Smuggling: Sensitive Joplin data is being dynamically injected into an external URL attribute (like `<img src="https://...">`) in a Webview. This can be used to silently exfiltrate sensitive data such as user notes or tokens to an attacker's server without requiring a direct network fetch.

### SEVERITY : WARNING

# Rule 11b : Remote Webview Scripts (Structural)
Detects webview HTML that directly references remote external resources.
It is a structural rule for literal or embedded HTML passed to Joplin webviews.

### Flows :
1. `setHtml()` receives HTML containing external `script` or `iframe` `src` URLs.
2. `setHtml()` receives HTML containing external `link` `href` URLs.
3. `setHtml()` receives HTML containing external meta refresh URLs.
4. `setHtml()` receives HTML containing external CSS `url(...)` references.

### Messages :
1. Remote Webview Resource: The plugin directly embeds an external URL in a Webview (via iframe, script, link, meta refresh, or CSS). Confirm the URL points to a trusted, known-good domain.

### SEVERITY : WARNING

# Rule 12 : Sync Smuggling (Intra-API Exfiltration)
Detects sensitive Joplin data being hidden in sync metadata or executed after retrieval.
It models abuse of `userDataSet()` and `userDataGet()` as an intra-API smuggling channel.

### Flows :
1. `joplin.data.get()` for `notes`, `folders`, `resources`, or `master_keys` flows into the value argument of `joplin.data.userDataSet(ModelType, itemId, key, value)`.
2. Data copied into `userDataSet()` is reported when its target model type and item ID do not match the source item.
3. `joplin.data.userDataGet()` flows into command execution.
4. `joplin.data.userDataGet()` flows into `eval`, `Function`, `setTimeout`, or `setInterval`.

### Messages :
1. Cross-item Sync Smuggling Indicator: Sensitive Joplin item data is being copied into another item's synchronized `userDataSet` metadata. Verify that this cross-item hidden storage is intentional and appropriate.
2. Sync Smuggling Execution: Hidden `userDataSet` content is being read out of the database and flowing directly into an execution sink. It indicates the plugin is reading payloads that were smuggled into the sync engine and executing them, serving as a stealthy Remote Code Execution (RCE).

### SEVERITY : ERROR

# Rule 13 : Social Engineering & UI Phishing
Detects Joplin dialogs or panels containing credential-entry controls whose submitted data leaves over the network.
It tracks form or message data from phishing-like UI into network sinks.

### Flows :
1. Dialog HTML containing password inputs or credential-labelled form controls is opened and its result flows into network request data or URLs.
2. Panel HTML containing password inputs or credential-labelled form controls is paired with `onMessage()` and submitted data flows into network request data or URLs.
3. The rule follows awaited dialog results and `.formData` property reads.
4. Provider or feature names such as GitHub, Dropbox, OneDrive, WebDAV, or sync do not make ordinary UI credential-looking by themselves.

### Messages :
1. UI Phishing Indicator: Data submitted through a credential-looking Joplin dialog or panel is being transmitted to an external network. Review the HTML and confirm that the interface and destination are legitimate.

### SEVERITY : ERROR

# Rule 14 : Asynchronous Tag Flooding & Search Poisoning
Detects high-volume Joplin data creation or disk writes inside loops.
It focuses on resource exhaustion through unbounded or repeated work.

### Flows :
1. `joplin.data.post()` to the exact `tags`, `notes`, `resources`, or `folders` collection route, or the exact tag-note link route, appears inside an unbounded loop or recurring timer.
2. Filesystem write, append, or output-file calls through Node `fs`, promise-based `fs`, `fs-extra`, or `joplin.require('fs-extra')` appear inside an unbounded loop or recurring timer.
3. String payloads larger than 10,000 characters or buffers larger than 10,000 bytes are written to disk inside any loop.
4. Operations reached through helpers called by the loop or timer are included; ordinary finite creation loops and cleared intervals are not treated as unbounded flooding.

### Messages :
1. Resource Exhaustion: The plugin is creating tags, notes, resources, folders, or tag-note links from an unbounded or background loop. Ensure loops have finite execution limits.
2. Disk Quota Exhaustion: The plugin is writing to the filesystem inside an unbounded or infinite loop. This will rapidly exhaust disk space. Ensure loops have finite execution limits.
3. Disk Quota Exhaustion: The plugin is writing large chunks of data to the filesystem inside a loop. Verify this is intended user-initiated behavior and won't overwhelm local storage.

### SEVERITY : WARNING

# Rule 15 : Semantic Integrity Sabotage (Gaslighting)
Detects note mutation performed directly inside Joplin workspace event hooks.
It is a structural rule for silent note changes triggered by user activity.

### Flows :
1. `joplin.data.put(["notes", noteId], ..., { body: "static replacement" })` appears inside note selection, note change, note content change, or alarm trigger callbacks.
2. A note update sets an active `deleted_time` or `is_conflict` value inside those callbacks.
3. `joplin.data.delete(["notes", noteId])` appears inside those workspace callbacks.
4. `joplin.commands.execute("insertText", ...)` or `replaceSelection` appears inside those workspace callbacks.
5. Mutations reached through helpers actually called by the workspace callback are included; nested helpers that are declared but never invoked are excluded.
6. Computed note bodies, inactive destructive values, note sub-routes, and mutations outside these workspace callbacks are not reported.

### Messages :
1. The plugin is mutating or deleting notes directly inside a workspace event hook (e.g., `onNoteSelectionChange`). Modifying a note the exact moment a user views or edits it can mimic "gaslighting" malware. Ensure these modifications are expected, visible formatting changes, not destructive silent edits.

### SEVERITY : ERROR

# Rule 16 : Electron Main Process Takeover
Detects direct access to Electron remote APIs.
It flags imports or member access that can expose privileged main-process capabilities when remote access is available.

### Flows :
1. Code imports `@electron/remote` or one of its package subpaths, such as `@electron/remote/main` or `@electron/remote/renderer`.
2. Code accesses `electron.remote`.
3. ES module imports, CommonJS requires, destructuring, namespace variables, and constant property access are covered by CodeQL's module model.

### Messages :
1. Critical Violation (Electron Remote Access): The plugin imports or accesses `@electron/remote` or `electron.remote`. If remote access is available, it can bypass Joplin's normal plugin API boundary and expose privileged Electron main-process capabilities. This unsupported access must be removed before publishing.

### SEVERITY : ERROR

# Rule 16b : Unauthorized Electron API Usage
Detects runtime member access on the native Electron module.
It flags Electron APIs that bypass the Joplin plugin API surface.

### Flows :
1. Code accesses a runtime member from `electron`, `electron/main`, `electron/renderer`, `electron/common`, or their `node:` variants.
2. Specifically classified APIs include windows, dialogs, application paths, clipboard, shell, IPC, display, session, networking, protocol, global shortcuts, desktop capture, safe storage, and utility processes.
3. Other runtime Electron properties receive one generic manual-review finding; the import itself does not produce a duplicate finding.
4. Type-only imports are excluded, and `electron.remote` is handled exclusively by Rule 16.

### Messages :
1. Unauthorized Native API Usage: The plugin accesses the runtime Electron API directly. Use Joplin panels or dialogs instead of creating native Electron windows.
2. Unauthorized Native API Usage: The plugin accesses the runtime Electron API directly. Use `joplin.views.dialogs` instead of `electron.dialog`.
3. Unauthorized Native API Usage: The plugin accesses the runtime Electron API directly. Use supported Joplin APIs such as `joplin.plugins.dataDir()` instead of Electron application paths.
4. Unauthorized Native API Usage: The plugin accesses the runtime Electron API directly. Use the `joplin.clipboard` API instead of `electron.clipboard`.
5. Unauthorized Native API Usage: The plugin accesses the runtime Electron API directly. Use Joplin's supported link handling instead of `electron.shell`.
6. Unauthorized Native API Usage: The plugin accesses the runtime Electron API directly. Direct Electron IPC bypasses Joplin's plugin messaging boundary.
7. Unauthorized Native API Usage: The plugin accesses the runtime Electron API directly. Direct display enumeration through `electron.screen` is outside the Joplin plugin API.
8. Unauthorized Native API Usage: The plugin accesses the runtime Electron API directly. This Electron networking or web-session API can bypass Joplin's managed application boundary.
9. Unauthorized Native API Usage: The plugin accesses the runtime Electron API directly. This Electron API can monitor global input or capture desktop content outside Joplin.
10. Unauthorized Native API Usage: The plugin accesses the runtime Electron API directly. This Electron API exposes privileged native storage or process capabilities outside the Joplin plugin API.
11. Unauthorized Native API Usage: The plugin accesses the runtime Electron API directly. Raw `electron.<property>` access is unsupported and must be reviewed for an equivalent Joplin API.

### SEVERITY : WARNING

# Rule 17 : Untrusted Archive Extraction
Detects remote or webview-controlled archive input being saved or passed to extraction.
It focuses on whether the archive source is trusted; Rule 17b exclusively validates the extraction destination.

### Flows :
1. Remote request data flows into a file that is later passed to `joplin.fs.archiveExtract()`.
2. Joplin webview message data flows into a file that is later passed to `joplin.fs.archiveExtract()`.
3. Remote or message-controlled data flows directly into the archive path argument of `archiveExtract()`.
4. File writes through Node `fs`, promise-based `fs`, `fs-extra`, or `joplin.require('fs-extra')` are covered, including common stream and pipeline downloads.
5. Merely passing data into `hash.update()` does not make the archive trusted; authenticity requires comparison with a trusted expected hash or verification of a digital signature.
6. Trusted local archive paths with no remote or webview-controlled flow are not reported.

### Messages :
1. Untrusted Archive Extraction: An archive obtained from a remote or webview-controlled source is being extracted. Confirm its origin and verify it against a trusted expected hash or digital signature before extraction. Destination safety is reviewed separately by the archive-destination rule.

### SEVERITY : WARNING

# Rule 17b : Unsafe Archive Extraction Destination
Detects archive extraction destinations derived from unsafe path sources.
It exclusively owns archive destination validation for paths outside the plugin data directory.

### Flows :
1. `process.env`, `process.argv`, `__dirname`, `__filename`, `joplin.plugins.installationDir()`, `process.cwd()`, `os.homedir()`, `os.tmpdir()`, plugin settings, or Electron application paths flow into the destination argument of `joplin.fs.archiveExtract()`.
2. Hardcoded absolute paths, working-directory-relative paths, Windows drive or UNC paths, and parent-directory traversal flow into the extraction destination.
3. Remote or Joplin webview-controlled input flows into the extraction destination.
4. `joplin.plugins.dataDir()` and paths formed from it using only fixed child segments are accepted.
5. Applying `path.dirname()` or parent traversal to `dataDir()` is reported because it escapes the plugin's storage boundary.
6. The query reports one result per unsafe destination rather than one result for every contributing path fragment.

### Messages :
1. Unsafe Extraction Destination: The archive destination is outside `joplin.plugins.dataDir()`, escapes it through parent traversal, or is controlled by an untrusted source. Use `dataDir()` with fixed child path segments and reject destinations that can escape that directory.

### SEVERITY : ERROR

# Rule 18 : Mass Data Destruction
Detects destructive Joplin data operations that can wipe or corrupt many records.
It is a structural rule for folder deletion, repeated deletion, and repeated destructive updates.

### Flows :
1. Any exact folder-item deletion through `joplin.data.delete(["folders", folderId])` is reported because deleting a folder cascades to its notes.
2. Any `joplin.data.delete()` reached directly or through a helper from an unbounded loop, uncleared interval, or recursive timeout is reported.
3. `joplin.data.put()` reached from a loop, recurring timer, or array iteration callback is reported when the payload sets an active `deleted_time`, sets `is_conflict`, or replaces `body` with an empty string.
4. Explicit inactive values such as `deleted_time: 0`, `is_conflict: false`, `null`, or `undefined` are excluded.
5. Merely opening a confirmation dialog does not suppress the finding; the reviewer must verify that the destructive action is correctly guarded by the user's response.

### Messages :
1. Mass Data Destruction: The plugin is deleting an entire folder (which cascades to all its notes). This can permanently destroy the user's database. Verify this is a legitimate bulk-management feature explicitly initiated by the user.
2. Mass Data Destruction: The plugin is looping unboundedly to delete many items at once. This can permanently destroy the user's database. Verify this is a legitimate bulk-management feature explicitly initiated by the user. If a loop is used, ensure it is bounded by finite, safe limits and not attacker-controlled.
3. Mass Data Destruction: The plugin is looping to soft-delete, wipe bodies, or flag conflicts on many items at once. This can effectively destroy the user's database. Verify this is a legitimate bulk-management feature explicitly initiated by the user. If a loop is used, ensure it is bounded by finite, safe limits and not attacker-controlled.

### SEVERITY : ERROR

# Rule 19 : Keylogging & Silent Surveillance
Detects live keyboard, input, or Joplin activity data that is sent over the network.
It tracks sensitive event parameters and Joplin data reads performed by event callbacks or invoked helpers.

### Flows :
1. Keyboard and text-input event parameters from `keydown`, `keyup`, `keypress`, `beforeinput`, `input`, or `paste` listeners flow into network request data or URLs.
2. Sensitive parameters from workspace activity hooks, `settings.onChange`, `filters.on`, `editors.onUpdate`, or editor `onActivationCheck` flow into network request data or URLs.
3. `selectedNote()`, `selectedNoteIds()`, `selectedFolder()`, or `selectedNoteHash()` reads inside monitored callbacks flow into network request data or URLs.
4. `joplin.data.get()` or `joplin.data.search()` reads performed directly or through an invoked helper from monitored callbacks flow into network request data or URLs.
5. Non-sensitive parameters from `onSyncComplete` and editor `onSetup` are excluded, although sensitive Joplin reads performed by those callbacks remain covered.
6. Generic UI messages and uncalled nested helpers are excluded from surveillance tracking.

### Messages :
1. Silent Surveillance / Keylogging: Live keyboard, input, Joplin activity, or data captured during an event is flowing to a network request. Verify that this collection and transmission is explicitly disclosed and authorized by the user.

### SEVERITY : ERROR

# Rule 20 : Malicious Import Module
Detects imported file paths or contents flowing from a custom import module into dangerous sinks.
It tracks data originating from the real `sourcePath` provided to `registerImportModule().onExec()`.

### Flows :
1. The `onExec` context's `sourcePath` flows directly into network requests, terminal commands, or unsafe filesystem operations.
2. Imported contents read through supported Node `fs`, promise-based `fs`, `fs-extra`, or `joplin.require('fs-extra')` APIs flow into those sinks.
3. Synchronous, promise, callback, JSON, and common read-stream forms are covered.
4. Inline objects, locally defined objects, factory-returned objects, and class instances registered as import modules are covered.
5. Writing or copying imported data under `joplin.plugins.dataDir()` is allowed; writes outside it and moves or renames of the original import source are reported.
6. Import options, warnings, unrelated functions named `readFile`, and legitimate creation of Joplin records are not treated as imported file contents.

### Messages :
1. Malicious Import Processing: An imported file path or its contents are flowing into a network request, terminal command, source-file mutation, or filesystem destination outside `joplin.plugins.dataDir()`. Verify that the import remains local and only creates expected Joplin data or files inside the plugin data directory.

### SEVERITY : ERROR
