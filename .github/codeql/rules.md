# Rule 1 : Dynamic Code Execution
Detects remote, message, or persisted user-data payloads that reach JavaScript execution APIs.
This rule is focused on code strings that can be evaluated at runtime.

### Flows :
1. Remote request results from `fetch`, `axios`, `http`, `https`, `got`, or `superagent` flow into execution sinks.
2. Message event callback data from windows, HTTP streams, WebSockets, workers, or Joplin webview messages flows into execution sinks.
3. `joplin.data.userDataGet()` payloads flow into execution sinks.
4. Execution sinks include `eval`, `Function`, string-based `setTimeout`, string-based `setInterval`, and `vm` execution APIs.

### SEVERTY : ERROR

# Rule 2 : Secret and Key Theft
Detects sensitive Joplin settings that flow into external or untrusted sinks.
It covers credential, sync, encryption, API token, client ID, and user identity settings.

### Flows :
1. `joplin.settings.globalValue()` or `globalValues()` for sensitive keys flows into network request data or URLs.
2. Sensitive settings flow into file paths or file contents being written.
3. Sensitive settings flow into command execution sinks.
4. Sensitive settings flow into Joplin data writes, hidden user data, or webview HTML sinks.

### SEVERTY : ERROR

# Rule 2b : Suspicious Sensitive Key Access
Detects direct reads of highly sensitive settings even when no exfiltration flow is proven.
It is a manual-review signal for suspicious credential access patterns.

### Flows :
1. Code reads `sync.*.password`, `api.token`, `encryption.cachedPpk`, or `encryption.passwordCache`.
2. Code reads both `encryption.masterPassword` and `syncInfoCache` in the same codebase.

### SEVERTY : WARNING

# Rule 3 : Unauthorized FS Access
Detects file operations that use path sources outside the plugin data directory.
It flags writes, moves, deletes, archive extraction destinations, and similar filesystem path sinks.

### Flows :
1. `__dirname`, `process.cwd()`, Electron app paths, `os.homedir()`, or `os.tmpdir()` flows into filesystem path sinks.
2. Native filesystem and `fs-extra` path arguments are treated as sinks for writes, moves, copies, deletes, renames, chmods, and directory operations.
3. `joplin.fs.archiveExtract()` destination paths are treated as filesystem path sinks.
4. Paths derived from `joplin.plugins.dataDir()` are excluded as safe destinations.

### SEVERTY : ERROR

# Rule 3b : Plugin Self-Modification
Detects plugins that attempt to modify their own installed package files.
It focuses on writes or deletes targeting common plugin entry and manifest files.

### Flows :
1. `__dirname`, `__filename`, or `joplin.plugins.installationDir()` flows into filesystem path sinks.
2. The same operation references plugin package files such as `index.js`, `main.js`, `plugin.js`, `manifest.json`, or `package.json`.

### SEVERTY : ERROR

# Rule 3c : Hardcoded Config Targeting
Detects hardcoded filesystem operations against sensitive local configuration paths.
It flags direct targeting of Joplin databases and SSH credential locations.

### Flows :
1. A filesystem path sink appears in a statement containing `.config/joplin-desktop`.
2. A filesystem path sink appears in a statement containing `database.sqlite`.
3. A filesystem path sink appears in a statement containing `.ssh`, `id_rsa`, or `authorized_keys`.

### SEVERTY : ERROR

# Rule 4 : Network Backdoor
Detects code that creates a server or socket and starts listening for inbound connections.
It covers Node networking modules and common web server frameworks.

### Flows :
1. `net`, `http`, `https`, `tls`, or `dgram` server/socket creation flows into `listen`, `bind`, or `start`.
2. `ws` or `socket.io` server creation flows into `listen`, `bind`, or `start`.
3. `express`, `koa`, or `fastify` app creation flows into `listen`, `bind`, or `start`.
4. Localhost-only binds are still reported by the rule.

### SEVERTY : ERROR

# Rule 5 : Clipboard Injection
Detects data being written back into the user's clipboard from risky sources.
It covers clipboard replacement using either remote data or existing clipboard content.

### Flows :
1. `joplin.clipboard.readText()` flows into `joplin.clipboard.writeText()` or `writeHtml()`.
2. Remote request results flow into `joplin.clipboard.writeText()` or `writeHtml()`.

### SEVERTY : ERROR

# Rule 5b : Clipboard Exfiltration
Detects clipboard contents being sent over the network.
It tracks reads from Joplin's clipboard API to outbound request sinks.

### Flows :
1. `joplin.clipboard.readText()` flows into network request data.
2. `joplin.clipboard.readText()` flows into network request URLs.

### SEVERTY : ERROR

# Rule 5c : Clipboard Execution
Detects clipboard contents being executed as code or commands.
It tracks clipboard reads into JavaScript execution and terminal execution sinks.

### Flows :
1. `joplin.clipboard.readText()` flows into child process or system command execution.
2. `joplin.clipboard.readText()` flows into `eval`, `Function`, `setTimeout`, or `setInterval`.

### SEVERTY : ERROR

# Rule 5d : Clipboard Hijacking (Background)
Detects repeated or background clipboard access.
It is a structural rule for clipboard reads or writes inside loops and timers.

### Flows :
1. `joplin.clipboard.readText()`, `writeText()`, or `writeHtml()` appears inside a loop.
2. Clipboard access appears inside a `setInterval` callback.
3. Clipboard access appears inside a recursive `setTimeout` callback.
4. Clipboard access appears inside `forEach` or `map` callbacks.

### SEVERTY : ERROR

# Rule 6 : Native Binary Dropping & Cryptojacking
Detects downloaded payloads or miner-related strings reaching command execution.
It is focused on native binary execution and cryptomining indicators.

### Flows :
1. Remote request results flow into child process or system command execution.
2. Strings containing miner indicators such as `xmrig`, `minerd`, `ethminer`, `pool.`, `stratum+tcp`, or `nicehash` flow into command execution.
3. Command execution with `shell: true` is included when the tainted value reaches the command arguments.

### SEVERTY : ERROR

# Rule 7 : Command Execution
Detects Joplin-controlled or user-controlled data reaching terminal command execution.
It excludes sensitive settings handled by the dedicated secret theft rule.

### Flows :
1. Non-sensitive `joplin.settings.globalValue()` or `globalValues()` results flow into command execution.
2. `joplin.data.get()`, `joplin.data.userDataGet()`, or `joplin.workspace.selectedNote()` flows into command execution.
3. Joplin workspace, panel, dialog, editor, or webview message callback parameters flow into command execution.

### SEVERTY : WARNING

# Rule 7b : Command Execution (Structural)
Detects hardcoded command strings passed to child process APIs.
It is a structural command execution indicator when no taint source is needed.

### Flows :
1. A string literal is passed directly to a command execution sink.
2. Miner-related hardcoded commands are excluded here because Rule 6 covers those indicators.

### SEVERTY : WARNING

# Rule 8 : Data Exfiltration
Detects note, folder, or resource data being sent to external network endpoints.
It covers bulk Joplin data reads and the currently selected note.

### Flows :
1. `joplin.data.get(["notes", ...])` flows into network request data or URLs.
2. `joplin.data.get(["folders", ...])` flows into network request data or URLs.
3. `joplin.data.get(["resources", ...])` flows into network request data or URLs.
4. `joplin.workspace.selectedNote()` flows into non-localhost network request data or URLs.

### SEVERTY : WARNING

# Rule 9 : Mass Encryption / Ransomware
Detects note data being encrypted and written back over the original note.
It models a multi-stage ransomware pattern rather than a single sink.

### Flows :
1. Joplin note data from `joplin.data.get(["notes", ...])` or `selectedNote()` flows into encryption calls.
2. Encryption output flows into `joplin.data.put(["notes", id], ...)`.
3. The read note ID and written note ID are correlated, including bulk note reads.
4. Writes inside loops are included in the detected pattern.

### SEVERTY : WARNING

# Rule 9b : Ransomware Key Exfiltration
Detects encryption key material being sent over the network.
It focuses on keys used for local encryption operations.

### Flows :
1. Key arguments to `createCipher()` or `createCipheriv()` flow into network request data or URLs.
2. Key arguments to `encrypt()` flow into network request data or URLs.
3. Key arguments to `importKey()` flow into network request data or URLs.

### SEVERTY : ERROR

# Rule 10 : Silent Backup Hijacking (Taint)
Detects export module data flowing into destinations outside the normal export path.
It tracks data from registered Joplin export callbacks to dangerous sinks.

### Flows :
1. `registerExportModule()` callback parameters from `onInit` or `onClose` flow into network, command, or unauthorized filesystem sinks.
2. `onProcessItem` callback parameters flow into network, command, or unauthorized filesystem sinks.
3. `onProcessResource` callback parameters flow into network, command, or unauthorized filesystem sinks.
4. File writes and file copies are excluded when their destination is derived from the export context destination path.

### SEVERTY : ERROR

# Rule 10b : Silent Backup Hijacking (Structural)
Detects dangerous operations inside export module callbacks without requiring proven taint flow.
It is a lower-confidence structural companion to Rule 10.

### Flows :
1. A network request call appears inside a `registerExportModule()` callback.
2. A command execution sink appears inside a `registerExportModule()` callback.
3. A filesystem path sink appears inside a `registerExportModule()` callback when the path is not derived from the export context.

### SEVERTY : WARNING

# Rule 11 : Remote Webview Scripts
Detects sensitive data being injected into external URLs inside Joplin webview HTML.
It covers URL-based exfiltration through dynamic HTML attributes.

### Flows :
1. `joplin.data.get()` results flow into externally hosted `script`, `iframe`, `img`, `link`, or `meta` URL attributes passed to `setHtml()`.
2. Sensitive `joplin.settings.globalValue()` results flow into externally hosted URL attributes passed to `setHtml()`.
3. `process.env` values flow into externally hosted URL attributes passed to `setHtml()`.
4. Panel, dialog, and editor `setHtml()` calls are covered.

### SEVERTY : WARNING

# Rule 11b : Remote Webview Scripts (Structural)
Detects webview HTML that directly references remote external resources.
It is a structural rule for literal or embedded HTML passed to Joplin webviews.

### Flows :
1. `setHtml()` receives HTML containing external `script` or `iframe` `src` URLs.
2. `setHtml()` receives HTML containing external `link` `href` URLs.
3. `setHtml()` receives HTML containing external meta refresh URLs.
4. `setHtml()` receives HTML containing external CSS `url(...)` references.

### SEVERTY : WARNING

# Rule 12 : Sync Smuggling (Intra-API Exfiltration)
Detects sensitive Joplin data being hidden in sync metadata or executed after retrieval.
It models abuse of `userDataSet()` and `userDataGet()` as an intra-API smuggling channel.

### Flows :
1. `joplin.data.get()` for `notes`, `folders`, `resources`, or `master_keys` flows into `joplin.data.userDataSet()`.
2. Data copied into `userDataSet()` is reported when it is not correlated to the same source item ID.
3. `joplin.data.userDataGet()` flows into command execution.
4. `joplin.data.userDataGet()` flows into `eval`, `Function`, `setTimeout`, or `setInterval`.

### SEVERTY : ERROR

# Rule 13 : Social Engineering & UI Phishing
Detects credential-looking Joplin dialogs or panels whose submitted data leaves over the network.
It tracks form or message data from phishing-like UI into network sinks.

### Flows :
1. Dialog HTML containing password fields or credential keywords is opened and its result flows into network request data or URLs.
2. Panel HTML containing password fields or credential keywords is paired with `onMessage()` and submitted data flows into network request data or URLs.
3. The rule follows awaited dialog results and `.formData` property reads.

### SEVERTY : ERROR

# Rule 14 : Asynchronous Tag Flooding & Search Poisoning
Detects high-volume Joplin data creation or disk writes inside loops.
It focuses on resource exhaustion through unbounded or repeated work.

### Flows :
1. `joplin.data.post()` to `tags`, `notes`, `resources`, or tag-note links appears inside an unbounded loop or background interval.
2. Filesystem writes appear inside an unbounded loop or background interval.
3. Large string or `Buffer.alloc()` payloads are written to disk inside any loop.

### SEVERTY : WARNING

# Rule 15 : Semantic Integrity Sabotage (Gaslighting)
Detects note mutation performed directly inside Joplin workspace event hooks.
It is a structural rule for silent note changes triggered by user activity.

### Flows :
1. `joplin.data.put(["notes", ...])` appears inside note selection, note change, note content change, or alarm trigger callbacks.
2. `joplin.data.delete(["notes", ...])` appears inside those workspace callbacks.
3. `joplin.commands.execute("insertText", ...)` or `replaceSelection` appears inside those workspace callbacks.

### SEVERTY : ERROR

# Rule 16 : Electron Main Process Takeover
Detects direct access to Electron remote APIs.
It flags imports or member access that can bypass normal plugin isolation.

### Flows :
1. Code imports `@electron/remote`.
2. Code accesses `electron.remote`.

### SEVERTY : ERROR

# Rule 16b : Unauthorized Electron API Usage
Detects direct imports or member access on the native Electron module.
It flags Electron APIs that bypass the Joplin plugin API surface.

### Flows :
1. Code imports the raw `electron` module.
2. Code accesses `electron.BrowserWindow`, `dialog`, `app`, `clipboard`, `shell`, `ipcRenderer`, `ipcMain`, or `screen`.

### SEVERTY : WARNING

# Rule 17 : Untrusted Archive Extraction
Detects remote or message-controlled archive input being extracted to unsafe destinations.
It excludes flows that pass through a crypto hash update barrier.

### Flows :
1. Remote request data flows into a file that is later passed to `joplin.fs.archiveExtract()`.
2. Joplin webview message data flows into a file that is later passed to `joplin.fs.archiveExtract()`.
3. Remote or message-controlled data flows directly into the archive path argument of `archiveExtract()`.
4. The destination is considered unsafe when no same-context `joplin.plugins.dataDir()` destination is found.

### SEVERTY : WARNING

# Rule 17b : Unsafe Archive Extraction Destination
Detects archive extraction destinations derived from unsafe path sources.
It focuses on destinations outside the plugin data directory.

### Flows :
1. `process.env`, `__dirname`, or `process.cwd()` flows into the destination argument of `joplin.fs.archiveExtract()`.
2. Hardcoded absolute paths flow into the destination argument of `archiveExtract()`.
3. Remote or user-controlled input flows into the destination argument of `archiveExtract()`.

### SEVERTY : ERROR

# Rule 17c : Archive Entry Traversal
Detects archive entry names flowing into filesystem or command sinks.
It models Zip Slip-style use of extracted entry names without sanitization.

### Flows :
1. The result of `joplin.fs.archiveExtract()` flows through `await`, `then`, array iteration, or array element reads.
2. Extracted entry `name` or `entryName` properties flow into filesystem path sinks.
3. Extracted entry `name` or `entryName` properties flow into command execution sinks.
4. `path.basename()` is treated as a sanitization barrier.

### SEVERTY : WARNING

# Rule 18 : Mass Data Destruction
Detects destructive Joplin data operations that can wipe or corrupt many records.
It is a structural rule for folder deletion, repeated deletion, and repeated destructive updates.

### Flows :
1. Any `joplin.data.delete(["folders", ...])` call is reported.
2. Any `joplin.data.delete()` call inside an unbounded loop or background interval is reported.
3. `joplin.data.put()` inside a loop is reported when the payload sets `deleted_time`, sets `is_conflict`, or replaces `body` with an empty string.

### SEVERTY : ERROR

# Rule 19 : Keylogging & Silent Surveillance
Detects event-driven user data capture that is sent over the network.
It tracks live Joplin hook data and data reads performed inside hook callbacks.

### Flows :
1. Parameters from workspace, settings, filter, panel, content script, or editor hooks flow into network request data or URLs.
2. `selectedNote()` or `selectedNoteIds()` reads inside those hooks flow into network request data or URLs.
3. `joplin.data.get()` or `joplin.data.search()` reads inside those hooks flow into network request data or URLs.
4. Editor registration callbacks such as `onActivationCheck` and `onSetup` are included.

### SEVERTY : ERROR

# Rule 20 : Malicious Import Module
Detects imported file data flowing from a custom import module into dangerous sinks.
It tracks data handled during `registerImportModule()` execution.

### Flows :
1. `registerImportModule()` `onExec` context or `sourcePath` flows into file read APIs.
2. Data read through `readFile`, `readFileSync`, `readJSON`, `readJSONSync`, or `readFileString` flows into dangerous sinks.
3. Dangerous sinks include network request data or URLs, command execution, filesystem paths, and filesystem write data.

### SEVERTY : WARNING
