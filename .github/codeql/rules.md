# Rule 1 : Dynamic Code Execution
Detects remote, message, or persisted user-data payloads that reach JavaScript execution APIs.
This rule is focused on code strings that can be evaluated at runtime.

### Flows :
1. Remote request results from `fetch`, `axios`, `http`, `https`, `got`, or `superagent` flow into execution sinks.
2. Message event callback data from windows, HTTP streams, WebSockets, workers, or Joplin webview messages flows into execution sinks.
3. `joplin.data.userDataGet()` payloads flow into execution sinks.
4. Execution sinks include `eval`, `Function`, string-based `setTimeout`, string-based `setInterval`, and `vm` execution APIs.

### SEVERITY : ERROR

# Rule 2 : Secret and Key Theft
Detects sensitive Joplin settings that flow into external or untrusted sinks.
It covers credential, sync, encryption, API token, client ID, and user identity settings.

### Flows :
1. `joplin.settings.globalValue()` or `globalValues()` for sensitive keys flows into network request data or URLs.
2. Sensitive settings flow into file paths or file contents being written.
3. Sensitive settings flow into command execution sinks.
4. Sensitive settings flow into Joplin data writes, hidden user data, or webview HTML sinks.

### SEVERITY : ERROR

# Rule 2b : Suspicious Sensitive Key Access
Detects direct reads of highly sensitive settings even when no exfiltration flow is proven.
It is a manual-review signal for suspicious credential access patterns.

### Flows :
1. Code reads `sync.*.password`, `api.token`, `encryption.cachedPpk`, or `encryption.passwordCache`.
2. Code reads both `encryption.masterPassword` and `syncInfoCache` in the same codebase.

### SEVERITY : WARNING

# Rule 3 : Unauthorized FS Access
Detects ordinary filesystem operations that use path sources outside the plugin data directory.
Archive extraction destinations are handled exclusively by Rule 17b.

### Flows :
1. `__dirname`, `process.cwd()`, Electron app paths, `os.homedir()`, or `os.tmpdir()` flows into filesystem path sinks.
2. Native filesystem and `fs-extra` path arguments are treated as sinks for writes, moves, copies, deletes, renames, chmods, and directory operations.
3. Paths based only on `joplin.plugins.dataDir()` remain safe, while paths mixed with unsafe sources or explicit parent-directory traversal are reported.

### SEVERITY : ERROR

# Rule 3b : Plugin Self-Modification
Detects plugins that attempt to modify their own installed package files.
It distinguishes a path being changed from a path that is only read or mentioned as file content.

### Flows :
1. `__filename` flows into a filesystem mutation target.
2. `joplin.plugins.installationDir()` and a protected package filename (`index.js`, `main.js`, `plugin.js`, `manifest.json`, or `package.json`) flow into the same mutation target.
3. Files that are only copied from the installation directory are not treated as modified, and archive destinations are handled by Rule 17b.

### SEVERITY : ERROR

# Rule 3c : Hardcoded Config Targeting
Detects hardcoded filesystem operations against sensitive local configuration paths.
It flags reads and mutations of Joplin profile files and SSH credential locations.

### Flows :
1. A hardcoded `.config/joplin-desktop` path flows into a filesystem read or mutation target, including its `database.sqlite` file.
2. A hardcoded `.ssh` path or complete `id_rsa` or `authorized_keys` filename flows into a filesystem read or mutation target.
3. Similar-looking filenames, unrelated `database.sqlite` files, and sensitive text used only as file content are not reported.
4. Archive extraction destinations are handled exclusively by Rule 17b.

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

### SEVERITY : ERROR

# Rule 5 : Clipboard Injection
Detects data being written back into the user's clipboard from risky sources.
It covers text, HTML, and image replacement using either remote data or existing clipboard content.

### Flows :
1. `joplin.clipboard.readText()`, `readHtml()`, or `readImage()` flows into a clipboard write operation.
2. Remote request results flow into `writeText()`, `writeHtml()`, `writeImage()`, or `write()`.

### SEVERITY : ERROR

# Rule 5b : Clipboard Exfiltration
Detects text, HTML, or image clipboard contents being sent over the network.
It tracks reads from Joplin's clipboard API to outbound request sinks.

### Flows :
1. `joplin.clipboard.readText()`, `readHtml()`, or `readImage()` flows into network request data.
2. `joplin.clipboard.readText()`, `readHtml()`, or `readImage()` flows into network request URLs.

### SEVERITY : ERROR

# Rule 5c : Clipboard Execution
Detects text or HTML clipboard contents being executed as code or commands.
It tracks clipboard reads into JavaScript execution and terminal execution sinks.

### Flows :
1. `joplin.clipboard.readText()` or `readHtml()` flows into child process or system command execution.
2. Clipboard text or HTML flows into the global `eval`, `Function`, string-based `setTimeout`, or string-based `setInterval` APIs.
3. Clipboard text or HTML flows into Node `vm` execution APIs such as `runInThisContext`, `runInNewContext`, `runInContext`, `compileFunction`, or `Script`.

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

### SEVERITY : WARNING

# Rule 9 : Mass Encryption / Ransomware
Detects note data being encrypted and written back over the original note.
It models a multi-stage ransomware pattern rather than a single sink.

### Flows :
1. Joplin note data from `joplin.data.get(["notes", ...])` or `selectedNote()` flows into a cipher `update()` or an `encrypt()` call.
2. Encryption output flows specifically into the `body` written by `joplin.data.put(["notes", id], ...)`.
3. The ID read from Joplin must match or flow into the exact write ID, including IDs derived from bulk note reads.
4. Writes executed repeatedly through loops, iteration callbacks, timers, or their helper functions are marked as bulk activity.

### SEVERITY : WARNING

# Rule 9b : Ransomware Key Exfiltration
Detects encryption key material being sent over the network.
It focuses on keys used for local encryption operations.

### Flows :
1. Key arguments to `createCipher()` or `createCipheriv()` flow into network request data or URLs.
2. Key arguments to WebCrypto or CryptoJS `encrypt()` operations flow into network request data or URLs.
3. The key-data argument to WebCrypto `importKey()` flows into network request data or URLs; its algorithm metadata is not treated as key material.
4. Key bytes returned by WebCrypto `exportKey()` flow into network request data or URLs.

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

### SEVERITY : WARNING

# Rule 11 : Remote Webview Scripts
Detects sensitive data being injected into external URLs inside Joplin webview HTML.
It covers URL-based exfiltration through dynamic HTML attributes.

### Flows :
1. `joplin.data.get()` results flow into externally hosted `script`, `iframe`, `img`, `link`, or `meta` URL attributes passed to `setHtml()`.
2. Sensitive `joplin.settings.globalValue()` results flow into externally hosted URL attributes passed to `setHtml()`.
3. Sensitive `process.env` values flow into externally hosted URL attributes passed to `setHtml()`.
4. Panel, dialog, and editor `setHtml()` calls are covered.

### SEVERITY : WARNING

# Rule 11b : Remote Webview Scripts (Structural)
Detects webview HTML that directly references remote external resources.
It is a structural rule for literal or embedded HTML passed to Joplin webviews.

### Flows :
1. `setHtml()` receives HTML containing external `script` or `iframe` `src` URLs.
2. `setHtml()` receives HTML containing external `link` `href` URLs.
3. `setHtml()` receives HTML containing external meta refresh URLs.
4. `setHtml()` receives HTML containing external CSS `url(...)` references.

### SEVERITY : WARNING

# Rule 12 : Sync Smuggling (Intra-API Exfiltration)
Detects sensitive Joplin data being hidden in sync metadata or executed after retrieval.
It models abuse of `userDataSet()` and `userDataGet()` as an intra-API smuggling channel.

### Flows :
1. `joplin.data.get()` for `notes`, `folders`, `resources`, or `master_keys` flows into the value argument of `joplin.data.userDataSet(ModelType, itemId, key, value)`.
2. Data copied into `userDataSet()` is reported when its target model type and item ID do not match the source item.
3. `joplin.data.userDataGet()` flows into command execution.
4. `joplin.data.userDataGet()` flows into `eval`, `Function`, `setTimeout`, or `setInterval`.

### SEVERITY : ERROR

# Rule 13 : Social Engineering & UI Phishing
Detects credential-looking Joplin dialogs or panels whose submitted data leaves over the network.
It tracks form or message data from phishing-like UI into network sinks.

### Flows :
1. Dialog HTML containing password fields or credential keywords is opened and its result flows into network request data or URLs.
2. Panel HTML containing password fields or credential keywords is paired with `onMessage()` and submitted data flows into network request data or URLs.
3. The rule follows awaited dialog results and `.formData` property reads.

### SEVERITY : ERROR

# Rule 14 : Asynchronous Tag Flooding & Search Poisoning
Detects high-volume Joplin data creation or disk writes inside loops.
It focuses on resource exhaustion through unbounded or repeated work.

### Flows :
1. `joplin.data.post()` to `tags`, `notes`, `resources`, or tag-note links appears inside an unbounded loop or background interval.
2. Filesystem writes appear inside an unbounded loop or background interval.
3. Large string or `Buffer.alloc()` payloads are written to disk inside any loop.

### SEVERITY : WARNING

# Rule 15 : Semantic Integrity Sabotage (Gaslighting)
Detects note mutation performed directly inside Joplin workspace event hooks.
It is a structural rule for silent note changes triggered by user activity.

### Flows :
1. `joplin.data.put(["notes", ...])` appears inside note selection, note change, note content change, or alarm trigger callbacks.
2. `joplin.data.delete(["notes", ...])` appears inside those workspace callbacks.
3. `joplin.commands.execute("insertText", ...)` or `replaceSelection` appears inside those workspace callbacks.

### SEVERITY : ERROR

# Rule 16 : Electron Main Process Takeover
Detects direct access to Electron remote APIs.
It flags imports or member access that can bypass normal plugin isolation.

### Flows :
1. Code imports `@electron/remote`.
2. Code accesses `electron.remote`.

### SEVERITY : ERROR

# Rule 16b : Unauthorized Electron API Usage
Detects direct imports or member access on the native Electron module.
It flags Electron APIs that bypass the Joplin plugin API surface.

### Flows :
1. Code imports the raw `electron` module.
2. Code accesses `electron.BrowserWindow`, `dialog`, `app`, `clipboard`, `shell`, `ipcRenderer`, `ipcMain`, or `screen`.

### SEVERITY : WARNING

# Rule 17 : Untrusted Archive Extraction
Detects remote or message-controlled archive input being extracted to unsafe destinations.
It excludes flows that pass into an `update(...)` call, which is intended to represent an integrity-check barrier.

### Flows :
1. Remote request data flows into a file that is later passed to `joplin.fs.archiveExtract()`.
2. Joplin webview message data flows into a file that is later passed to `joplin.fs.archiveExtract()`.
3. Remote or message-controlled data flows directly into the archive path argument of `archiveExtract()`.
4. The destination is considered unsafe when no same-context `joplin.plugins.dataDir()` destination is found.

### SEVERITY : WARNING

# Rule 17b : Unsafe Archive Extraction Destination
Detects archive extraction destinations derived from unsafe path sources.
It exclusively owns archive destination validation for paths outside the plugin data directory.

### Flows :
1. `process.env`, `__dirname`, `__filename`, `joplin.plugins.installationDir()`, `process.cwd()`, `os.homedir()`, `os.tmpdir()`, or Electron application paths flow into the destination argument of `joplin.fs.archiveExtract()`.
2. Hardcoded absolute paths flow into the destination argument of `archiveExtract()`.
3. Remote or user-controlled input flows into the destination argument of `archiveExtract()`.

### SEVERITY : ERROR

# Rule 17c : Archive Entry Traversal
Detects archive entry names flowing into filesystem or command sinks.
It models Zip Slip-style use of extracted entry names without sanitization.

### Flows :
1. The result of `joplin.fs.archiveExtract()` flows through `await`, `then`, array iteration, or array element reads.
2. Extracted entry `name` or `entryName` properties flow into filesystem path sinks.
3. Extracted entry `name` or `entryName` properties flow into command execution sinks.
4. `path.basename()` is treated as a sanitization barrier.

### SEVERITY : WARNING

# Rule 18 : Mass Data Destruction
Detects destructive Joplin data operations that can wipe or corrupt many records.
It is a structural rule for folder deletion, repeated deletion, and repeated destructive updates.

### Flows :
1. Any `joplin.data.delete(["folders", ...])` call is reported unless a Joplin confirmation dialog is opened in the same function.
2. Any `joplin.data.delete()` call inside an unbounded loop or background interval is reported.
3. `joplin.data.put()` inside a loop is reported when the payload sets `deleted_time`, sets `is_conflict`, or replaces `body` with an empty string.
4. Destructive operations are excluded when the same function also calls `joplin.views.dialogs.open(...)`; the rule does not verify call order or the user's response.

### SEVERITY : ERROR

# Rule 19 : Keylogging & Silent Surveillance
Detects event-driven user data capture that is sent over the network.
It tracks live Joplin hook data and data reads performed inside hook callbacks.

### Flows :
1. Parameters from workspace hooks (`onNoteContentChange`, `onNoteChange`, `onNoteSelectionChange`, `onSyncComplete`, `onResourceChange`, or `onNoteAlarmTrigger`), `settings.onChange`, `filters.on`, or `editors.onUpdate` flow into network request data or URLs.
2. `selectedNote()` or `selectedNoteIds()` reads inside those hooks, including `onSyncStart`, flow into network request data or URLs.
3. `joplin.data.get()` or `joplin.data.search()` reads inside those hooks flow into network request data or URLs.
4. Editor registration callbacks such as `onActivationCheck` and `onSetup` are included.
5. Generic UI message handlers (`contentScripts.onMessage` or `panels.onMessage`) are excluded from surveillance tracking.

### SEVERITY : ERROR

# Rule 20 : Malicious Import Module
Detects imported file data flowing from a custom import module into dangerous sinks.
It tracks data handled during `registerImportModule()` execution.

### Flows :
1. `registerImportModule()` `onExec` context or `sourcePath` flows into file read APIs.
2. Data read through `readFile`, `readFileSync`, `readJSON`, `readJSONSync`, or `readFileString` flows into dangerous sinks.
3. Dangerous sinks include network request data or URLs, command execution, filesystem paths, and filesystem write data.

### SEVERITY : WARNING
