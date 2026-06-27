# Rule 1 : Dynamic Code Execution

  Detects dynamic code execution from remote sources. Covers both "fetch remote code" and "receive code via event" entry points. Flags cases where
  untrusted/remote content is executed as code rather than treated as data.

  ### Flows :

  1.  fetch() / axios.get() / http.get()  call result ->  eval()  argument
  2.  fetch() / http.get()  call result ->  new Function()  argument
  3.  fetch() / http.get()  call result ->  setTimeout() / setInterval()  first argument (string-as-code form)
  4.  fetch() / http.get()  call result ->  vm.runInNewContext()  /  Script()  argument
  5. "message"/"data" event listener callback's parameter 0 -> same set of sinks above

  ### Messages :

  Remote data flows to dynamic code execution (e.g., `eval`, `setTimeout`, or `Function`). 
**Reviewer Action:** Verify if the endpoint is a trusted Joplin service or a remote server. If code execution is intended, check for strict code signing, content-hash validation, or sandboxing to ensure an attacker cannot inject arbitrary payloads via the network.

  ### Severity : error

# Rule 2 : Secret and Key Theft

  Detects Joplin's internal sensitive settings (sync cache, master password, API tokens, cached encryption keys) flowing into exfiltration-capable sinks.

  ### Flows :

  1.  joplin.settings.globalValue("encryption.masterPassword" / "api.token" / etc)  -> network sink (fetch/axios/http/WebSocket)
  2.  joplin.settings.globalValue(sensitive setting)  -> filesystem path sink (writeFile/rename/unlink path argument)
  3.  joplin.settings.globalValue(sensitive setting)  -> filesystem data sink (writeFile content argument)
  4.  joplin.settings.globalValue(sensitive setting)  -> command execution sink (child_process argument)
  5.  joplin.settings.globalValue(sensitive setting)  -> Joplin-specific sink (joplin.data.put or panels.setHtml)
  6. Same flows via  globalValues()  array form.

  ### Messages :

  Critical Security Alert: Sensitive configuration data (such as a master password, sync cache, encryption keys, or API tokens) is flowing directly to an external or untrusted sink. 
**Reviewer Action:** This is highly suspicious behavior. Confirm whether the plugin has a legitimate, fully disclosed reason to touch credentials. Ensure this data is never exposed to network logs, user-interface text panels, or unencrypted local cache files.

  ### Severity : error

   # Rule 3 : Unauthorized FS Access / Self-Modification

  Detects filesystem-path-revealing sources (process.cwd, __dirname) flowing into destructive/path-based fs operations, skipping whitelisted safe sandbox
  destinations.

  ### Flows :

  1.  __dirname  /  __filename  -> filesystem path sink (writeFile/rm/etc.)
  2.  process.cwd()  -> filesystem path sink
  3.  app.getPath()  -> filesystem path sink
  4.  os.homedir()  -> filesystem path sink
  5.  path.resolve()  /  path.join()  -> filesystem path sink
  6.  joplin.plugins.dataDir  -> filesystem path sink
  7.  require("fs")  /  import fs  module reference -> filesystem path sink

  ### Messages :

  Unauthorized File System Access: The plugin is using path-revealing variables (like `__dirname` or `process.cwd`) to write, modify, or delete files outside of the safe Joplin sandbox. 
**Reviewer Action:** Plugins must exclusively use `joplin.plugins.dataDir()` for file storage. Reject this if it is attempting to modify the plugin's own source files or blindly access the user's broader OS file system.

  ### Severity : error

   # Rule 4 : Network Backdoor

  Detects server-creation objects flowing into a receiver of  .listen() / .bind() / .start()  to open a local port.

  ### Flows :

  1.  net.createServer()  /  http.createServer()  result -> receiver of  .listen()  call
  2.  dgram.createSocket()  result -> receiver of  .bind()  call
  3.  new ws.Server(...)  instance -> receiver of  .listen() / .start()  call
  4.  express()  /  koa()  /  fastify()  app instance -> receiver of  .listen()  call

  ### Messages :

  Network Backdoor Detected: The plugin is opening a local listening port (via `net`, `http`, or frameworks like `Express`) to accept incoming connections. 
**Reviewer Action:** Check if the plugin explicitly advertises running a local server (e.g., a companion web app). If this is undocumented, it acts as a backdoor. Verify that the server binds securely (e.g., localhost only) and requires explicit authentication.

  ### Severity : error

   # Rule 5 : Clipboard Hijacking

  Detects clipboard content being read out and/or replaced with externally-sourced or arbitrary string data.

  ### Flows :

  1.  joplin.clipboard.readText()  -> argument of  clipboard.writeText() / writeHtml()
  2.  fetch()  call result -> argument of  clipboard.writeText() / writeHtml()
  3. Any string literal -> argument of  clipboard.writeText() / writeHtml()

  ### Messages :

  Clipboard Hijacking Risk: The plugin is reading the user's clipboard and replacing it with arbitrary external data or hardcoded strings. 
**Reviewer Action:** Verify that this is triggered by a deliberate user action (like clicking a "Copy" button). If this happens silently in the background, it may be attempting to swap copied text (e.g., injecting cryptocurrency wallet addresses or malicious URLs).

  ### Severity : error

   # Rule 6 : Native Binary Dropping & Cryptojacking

  Detects remote data or known cryptominer keywords flowing into a command-execution sink, with severity escalation if  {shell: true}  is passed.

  ### Flows :

  1.  fetch()  call result -> command execution sink (child_process argument)
  2. String literal matching xmrig/minerd/ethminer/cgminer/t-rex/nsfminer/pool/stratum+tcp -> command execution sink
  3. (Escalation)  spawn() / execFile()  options contains  {shell: true}

  ### Messages :

  High-Risk Execution: The plugin is downloading external payloads or contains hardcoded keywords associated with cryptominers, and passing them directly to a system terminal command. 
**Reviewer Action:** This is a severe threat indicator. If `shell: true` is also flagged, the severity is elevated. Immediately audit the command payload to ensure it is not silently installing malware or hijacking CPU resources.

  ### Severity : error

  #  Rule 7 : Command Execution

  A residual catch-all detecting non-sensitive settings, note data reads, selected notes, and generic parameters flowing into a command execution sink.

  ### Flows :

  1.  joplin.settings.globalValue()  (where setting is NOT sensitive) -> command execution sink
  2.  joplin.data.get()  -> command execution sink
  3.  joplin.workspace.selectedNote()  -> command execution sink
  4. Any function parameter -> command execution sink
  5. Any string literal NOT matching miner keywords -> command execution sink

  ### Messages :

  Terminal Command Execution: The plugin is passing generic string data or Joplin settings into a system terminal command (`child_process`). 
**Reviewer Action:** Note: this is the broadest, lowest-specificity command-execution check — cross-reference with Rule 2 (Secret Theft) and Rule 6 (Cryptojacking) if this same call also appears there. Review the executed command to ensure the inputs are properly sanitized against command injection.

  ### Severity : warning

   # # Rule 8 : Data Exfiltration

  Detects bulk-reading notes or resources and piping the full-list data into network requests.

  ### Flows :

  1.  joplin.data.get(["notes"])  (no ID, full list) -> network exfiltration sink
  2.  joplin.data.get(["folders"])  (no ID, full list) -> network exfiltration sink
  3.  joplin.data.get(["resources"])  (no ID, full list) -> network exfiltration sink
  4.  joplin.workspace.selectedNote()  -> network exfiltration sink

  ### Messages :

  Data Exfiltration Warning: The plugin is executing a bulk-read of notes, folders, or resources, and immediately sending that data to an external network request. 
**Reviewer Action:** Check if the plugin is a legitimate sync/export tool. If not, this is a massive privacy breach. Verify exactly what data is being sent in the payload and ensure the destination server is trusted and expected by the user.

  ### Severity : error

   # Rule 9 : Mass Encryption / Ransomware

  Three-stage taint tracking connecting note reads to encryption algorithms and then back to Joplin data overwrites via same-note correlation.

  ### Flows :

  1.  joplin.data.get() / selectedNote()  -> argument of  cipher.update() / encrypt()
  2. Encryption call result -> argument of  joplin.data.put()
  3. Same-note correlation 1: Read source itself flows into the ID slot of the write call's path
  4. Same-note correlation 2: Read call's ID matches the write call's ID exactly

  ### Messages :

  Ransomware Pattern Detected: The plugin is reading Joplin notes, passing them through an encryption cipher, and overwriting the original notes. 
**Reviewer Action:** Unless this plugin is explicitly designed as an end-to-end encryption tool, this behavior mimics ransomware. Verify that the user holds the decryption keys locally and that this action is strictly opt-in.

  ### Severity : warning

   # Rule 10 : Silent Backup Hijacking (Taint + Structural)

  Detects data from an export module flowing into a network, child_process, or unauthorized file system sink (bypassing the legitimate export path).

  ### Flows :

  1.  onProcessItem / onProcessResource  parameters -> network exfiltration sink
  2.  onInit / onClose  context parameter -> network exfiltration sink
  3. Any of the above source parameters -> command execution sink
  4. Any of the above source parameters -> file-write data sink (ONLY IF destination path is NOT tainted by context)
  5. (Structural Variant): Any network/exec/file-write call lexically inside a  registerExportModule  callback.

  ### Messages :

  [High Confidence] Backup Hijacking Alert: Export data is confirmed flowing into a network request, terminal command, or unauthorized file path instead of the legitimate export destination. 
**Reviewer Action:** Verify if the plugin is quietly siphoning off backup data during a user-initiated export. Ensure all exported data strictly writes to the context's designated safe destination path.

  [Low Confidence] Backup Hijacking Indicator: A network, execution, or file-write call exists lexically inside an export callback, but direct data flow isn't confirmed by taint tracking. 
**Reviewer Action:** Manual trace required. Verify if the execution/network call is legitimately part of the export process or if it is acting as a blind trigger/exfiltration vector.

  ### Severity : error (Taint) / warning (Structural)

  #  Rule 11 : Remote Webview Scripts (Taint + Structural)

  Detects creating a webview or content script with an external remote URL dynamically (excluding safe localhost/local files).

  ### Flows :

  1.  fetch()  response ->  setHtml()  HTML argument (containing  <script/> / <iframe/> )
  2.  axios.get()  /  process.env  /  settings  ->  setHtml()  HTML argument
  3. Hardcoded external URL string literal ->  setHtml()  HTML argument
  4. Same sources ->  contentScripts.register()  third argument
  5. (Structural Variant): Any  setHtml()  or  contentScripts.register()  regardless of source.

  ### Messages :

  Remote Webview Injection: The plugin is dynamically loading an external, remote URL into a Webview (via iframe or script tags) or registering a remote Content Script. 
**Reviewer Action:** Confirm the URL points to a trusted, known-good domain (like a CDN or official docs). Loading unverified remote scripts allows an attacker to bypass plugin updates and dynamically execute malicious UI code.

  URL Smuggling: Sensitive data (note content or settings) flows directly into a Webview URL or HTML payload.
**Reviewer Action:** Verify that sensitive user data is not being appended as query parameters to external image tags (`<img src=".../?data=SECRET">`) or remote iframes, which silently exfiltrates the data to external server logs.

  ### Severity : warning

  #  Rule 12 : Sync Smuggling (Intra-API Exfiltration)

  Exfiltrating sensitive user data by smuggling it into internal  userDataSet  sync values.

  ### Flows :

  1.  joplin.data.get(["notes", id])  -> any argument of  joplin.data.userDataSet()
  2.  joplin.data.get(["folders"|"resources"|"master_keys", id])  -> any argument of  userDataSet()

  ### Messages :

  Sync Smuggling Attempt: Sensitive note, folder, or key data is being copied and hidden inside a note's invisible `userDataSet` property. 
**Reviewer Action:** This is a stealth exfiltration technique. Verify why the plugin needs to duplicate sensitive content into hidden metadata fields that the user cannot easily inspect.

  Sync Smuggling Execution: Hidden `userDataSet` content is being read out of the database and flowing directly into an execution or network sink.
**Reviewer Action:** This is highly dangerous. It indicates the plugin is reading payloads that were smuggled into the sync engine and executing them, serving as a stealthy Remote Code Execution (RCE) or exfiltration trigger.

  ### Severity : error

  #  Rule 13 : Social Engineering & UI Phishing

  Spoofing internal authentication interfaces to harvest credentials.

  ### Flows :

  1. Joplin dialog submission / prompt result -> network exfiltration sink

  ### Messages :

  UI Phishing Indicator: Data submitted through a custom Joplin dialog or prompt is being transmitted to an external network. 
**Reviewer Action:** Review the HTML of the dialog. Ensure it is not mimicking an official Joplin authentication screen or asking for external service credentials (like GitHub or Dropbox) over an untrusted connection.

  ### Severity : error

 #   Rule 14 : Asynchronous Tag Flooding & Search Poisoning

  Sabotaging application indexing via programmatic high-volume metadata inflation using unbounded loops.

  ### Flows :

  1.  joplin.data.post(["tags"|"notes"|"resources", ...])  inside an unbounded  setInterval  (no  clearInterval )
  2.  joplin.data.post()  inside a synchronous  for / while / do-while  loop statement

  ### Messages :

  Resource Exhaustion (Flooding): The plugin is rapidly creating tags, notes, or resources inside an unbounded background interval or synchronous loop. 
**Reviewer Action:** This can destroy Joplin's search index and exhaust storage quotas. Confirm the loop is strictly bounded by a finite limit (e.g., iterating only over user-selected notes) and is not infinite.

  ### Severity : warning

 #   Rule 15 : Semantic Integrity Sabotage (Gaslighting)

  Silently modifying user notes in a malicious or destabilizing manner using hooks.

  ### Flows :

  1.  workspace.onNoteSelectionChange()  callback body ->  joplin.data.put() / delete()  in the same function
  2.  workspace.onNoteChange()  /  onNoteContentChange()  callback body ->  joplin.data.put() / delete()  in the same function

  ### Messages :

  Semantic Sabotage: The plugin is silently modifying or deleting notes directly inside a workspace event hook (like `onNoteSelectionChange`). 
**Reviewer Action:** Modifying a note the exact moment a user clicks on it is highly suspicious and mimics "gaslighting" malware. Ensure these modifications are expected, visible formatting changes (like an auto-linter), not destructive silent edits.

  ### Severity : error

  #  Rule 16 : Electron Main Process Takeover

  Gaining direct access to the main Electron process to control the app window or bypass renderer restrictions.

  ### Flows :

  1.  require("@electron/remote")  or  import ... from "@electron/remote"
  2.  require("electron").remote  or  import  access to  electron.remote

  ### Messages :

  Critical Violation (Main Process Takeover): The plugin is attempting to import or require `@electron/remote` or `electron.remote`. 
**Reviewer Action:** This completely bypasses the plugin sandbox and grants full control over the Joplin application window and the OS. This must be strictly prohibited and removed before publishing.

  ### Severity : error

 #   Rule 16b : Unauthorized Electron API Usage

  Direct usage of native Electron APIs bypasses Joplin's sanctioned plugin architecture.

  ### Flows :

  1.  require("electron")  /  import "electron"  (bare import)
  2.  electron.BrowserWindow  /  dialog  /  app  /  clipboard  /  shell  /  ipcRenderer  /  ipcMain  /  screen

  ### Messages :

  Unauthorized Native API Usage: The plugin is importing the raw `electron` module directly. 
**Reviewer Action:** Direct Electron API usage bypasses Joplin's sanctioned architecture. Verify which property is being accessed (e.g., clipboard, dialog). Instruct the developer to use the equivalent official Joplin API (e.g., `joplin.clipboard`) instead.

  ### Severity : warning

 #   Rule 17a : Untrusted Archive Extraction

  Extracting untrusted archives from the network can lead to malicious file overwrites.

  ### Flows :

  1.  fetch() / axios.get()  response ->  writeFile() / writeFileSync()  data argument
  2. That write call's path argument correlates with  archiveExtract() 's sourcePath argument

  ### Messages :

  Unsafe Archive Extraction: An archive downloaded directly from the network is being extracted onto the local disk. 
**Reviewer Action:** This can lead to arbitrary file overwrites. Verify that the archive source is trusted, and that the extraction logic strictly validates the archive contents before unzipping.

  ### Severity : warning

  #  Rule 17b : Unsafe Archive Extraction Destination

  Extracting archives to paths outside the plugin's data directory can overwrite sensitive files.

  ### Flows :

  1.  joplin.plugins.dataDir()  ->  archiveExtract()  destinationPath argument (allowed flow)
  2. Final alert fires when NO such flow exists -> destination is unsafe/unrelated to data directory

  ### Messages :

  Unsafe Extraction Destination: An archive is being extracted to a path outside of the plugin's isolated data directory. 
**Reviewer Action:** Extraction paths must be strictly derived from `joplin.plugins.dataDir()`. Reject this if it risks overwriting user configuration files or core Joplin application data.

  ### Severity : warning

  #  Rule 17c : Archive Entry Traversal

  Using unsanitized archive entry names in filesystem paths can lead to path traversal vulnerabilities.

  ### Flows :

  1.  archiveExtract()  call result -> individual  ArchiveEntry  object ->  .name  /  .entryName  read -> filesystem path sink

  ### Messages :

  Path Traversal Risk (Zip Slip): Unsanitized file names from inside an extracted archive are flowing directly into file system paths. 
**Reviewer Action:** Ensure the plugin sanitizes archive entry names (e.g., blocking `../` sequences) before writing them to disk to prevent "Zip Slip" vulnerabilities from overwriting sensitive files outside the target directory.

  ### Severity : warning

#    Rule 17d : Third-Party Archive Extraction

  Usage of third-party archive extraction libraries, which may lack necessary path validation.

  ### Flows :

  1.  import / require  of  extract-zip ,  yauzl ,  adm-zip , or  tar

  ### Messages :

  Third-Party Extractor Warning: The plugin is using an external library (like `extract-zip`, `adm-zip`, or `tar`) to unpack archives. 
**Reviewer Action:** Third-party extractors often lack native path validation. Manually audit the extraction flow to ensure the developer has implemented robust source validation and directory traversal prevention.

  ### Severity : warning

  #  Rule 18 : Mass Data Destruction

  Iterating through notes/folders to permanently destroy the database.

  ### Flows :

  1.  joplin.data.delete(["folders", ...])  (cascading destruction, flagged unconditionally)
  2.  joplin.data.delete(...)  inside a synchronous loop OR an unbounded  setInterval  callback
  3.  joplin.data.put(...)  inside a loop, where payload sets  deleted_time  or  is_conflict

  ### Messages :

  Mass Data Destruction: The plugin is either deleting an entire folder (which cascades to all its notes) or looping to delete/soft-delete many items at once.
**Reviewer Action:** This can permanently destroy the user's database. Verify this is a legitimate bulk-management feature explicitly initiated by the user. If a loop is used, ensure it is bounded by finite, safe limits and not attacker-controlled.

  ### Severity : warning

  #  Rule 19 : Keylogging & Silent Surveillance

  Monitoring user notes and exfiltrating data.

  ### Flows :

  1.  workspace.onNoteContentChange / onNoteChange / onNoteSelectionChange / onSyncStart / onSyncComplete / onResourceChange / onNoteAlarmTrigger
  callback parameter -> network exfiltration sink
  2.  settings.onChange  /  editor.onUpdate  /  filters.on  /  panels.onMessage  callback parameter -> network exfiltration sink

  ### Messages :

  Silent Surveillance / Hook Exfiltration: Data captured from a workspace, settings, or sync event hook is being funneled directly to a network endpoint. 
**Reviewer Action:** This captures live user activity (e.g., settings changes, post-sync harvesting, or editor keystrokes). Ensure the plugin has explicit user consent to transmit telemetry or data state changes, and verify the endpoint is secure.

  ### Severity : error

 #   Rule 20 : Native Module Imports

  Bypassing  joplin.require  to gain host access.

  ### Flows :

  1.  require() / import  of  fs ,  net ,  os ,  dgram ,  child_process ,  tls ,  http ,  https ,  sqlite3 , or  better-sqlite3  (with or without "node:"
  prefix)

  ### Messages :

  Sandbox Bypass (Native Import): The plugin is directly requiring a core Node.js native module (like `fs`, `net`, or `child_process`) without using `joplin.require`. 
**Reviewer Action:** Direct native imports evade Joplin's permission and wrapper systems. Instruct the developer to switch to `joplin.require('module-name')` to ensure standard security policies and hooks apply.

  ### Severity : error

  #  Rule 21 : Malicious Import Module

  Detects if data read from an imported file inside  registerImportModule  flows to a dangerous sink.

  ### Flows :

  1.  onExec  callback's context parameter -> network exfiltration sink
  2.  onExec  callback's context parameter ->  context.sourcePath  ->  readFile / readJSON  -> network or command execution sink

  ### Messages :

  Malicious Import Processing: Data read during a custom `registerImportModule` execution is flowing into a dangerous sink (network exfiltration or OS command execution). 
**Reviewer Action:** Importing a note should only result in note creation. Verify why the plugin needs to execute commands or phone home based on the contents of an imported file. Ensure strict sanitization.

  ### Severity : warning
