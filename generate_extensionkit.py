#!/usr/bin/env python3
"""
Generate Forge-compatible extension.json files for the AdaptixC2 Extension-Kit.

This script uses a curated command registry derived from reading every .axs file
in the Extension-Kit to generate Forge-compatible extension.json descriptors,
copy compiled COFF .o binaries, and produce source metadata for Mythic Forge.

Forge argument types (from forge_download.go):
  b/file   -> COMMAND_PARAMETER_TYPE_FILE
  i/int    -> COMMAND_PARAMETER_TYPE_NUMBER
  s/short  -> COMMAND_PARAMETER_TYPE_NUMBER
  z/string -> COMMAND_PARAMETER_TYPE_STRING
  Z/wstring-> COMMAND_PARAMETER_TYPE_STRING
"""

import json
import os
import shutil
from pathlib import Path

# ==============================================================================
# Configuration
# ==============================================================================

EXTENSION_KIT_DIR = Path("/workspace/forge/Extension-Kit")
FORGE_COLLECTIONS_DIR = Path("/workspace/forge/Payload_Type/forge/forge/collections/ExtensionKit")
FORGE_BASE_DIR = Path("/workspace/forge/Payload_Type/forge")

# ==============================================================================
# Command Registry
# Each entry defines a BOF command extracted from the .axs files.
# Format:
#   cmd:    Command name in Forge
#   desc:   Command description
#   bof:    BOF file base name in Extension-Kit
#   module: Subdirectory in Extension-Kit
#   args:   List of tuples (name, type, description, optional, default)
# ==============================================================================

COMMANDS = [
    # =========================================================================
    # SAL-BOF (sal.axs) - Situational Awareness Local
    # =========================================================================
    {
        "cmd": "arp", "desc": "List ARP table",
        "bof": "arp", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "cacls", "desc": "List user permissions for the specified file or directory, wildcards supported",
        "bof": "cacls", "module": "SAL-BOF",
        "args": [("path", "Z", "File or directory path", False, None)]
    },
    {
        "cmd": "ek-dir", "desc": "Lists files in a specified directory. Supports wildcards and optional recursive listing",
        "bof": "dir", "module": "SAL-BOF",
        "args": [
            ("directory", "Z", "Directory to list", True, ".\\\\"),
            ("recursive", "i", "Recursive list (1=yes, 0=no)", True, 0),
        ]
    },
    {
        "cmd": "ek-env", "desc": "List process environment variables",
        "bof": "env", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "ek-ipconfig", "desc": "List IPv4 address, hostname, and DNS server",
        "bof": "ipconfig", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "listdns", "desc": "List DNS cache entries. Attempt to query and resolve each",
        "bof": "listdns", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "ek-netstat", "desc": "Executes the netstat command to display network connections",
        "bof": "netstat", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "ek-nslookup", "desc": "Make a DNS query",
        "bof": "nslookup", "module": "SAL-BOF",
        "args": [
            ("domain", "z", "Domain to query", False, None),
            ("type", "z", "Record type (A, AAAA, ANY)", True, "A"),
            ("server", "z", "DNS server to query", True, ""),
        ]
    },
    {
        "cmd": "routeprint", "desc": "List IPv4 routes",
        "bof": "routeprint", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "ek-uptime", "desc": "List system boot time and how long it has been running",
        "bof": "uptime", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "useridletime", "desc": "Shows how long the user has been idle",
        "bof": "useridletime", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "ek-whoami", "desc": "List whoami /all",
        "bof": "whoami", "module": "SAL-BOF", "args": []
    },
    # SAL-BOF privcheck subcommands
    {
        "cmd": "alwayselevated", "desc": "Checks if Always Install Elevated is enabled using the registry",
        "bof": "alwayselevated", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "hijackablepath", "desc": "Checks the path environment variable for writable directories that can be exploited",
        "bof": "hijackablepath", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "tokenpriv", "desc": "Lists the current token privileges and highlights known vulnerable ones",
        "bof": "tokenpriv", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "unattendfiles", "desc": "Checks for leftover unattend files that might contain sensitive information",
        "bof": "unattendfiles", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "unquotedsvc", "desc": "Checks for unquoted service paths",
        "bof": "unquotedsvc", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "vulndrivers", "desc": "Checks if any service uses a known vulnerable driver (loldrivers.io)",
        "bof": "vulndrivers", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "ek-autologon", "desc": "Checks for stored Autologon credentials in Winlogon registry key",
        "bof": "autologon", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "ek-credmanager", "desc": "Enumerates credentials stored in Windows Credential Manager",
        "bof": "credmanager", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "modautorun", "desc": "Checks for modifiable autorun executables in Run/RunOnce registry keys",
        "bof": "modautorun", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "modsvc", "desc": "Checks for services with modifiable permissions (DACL)",
        "bof": "modsvc", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "pshistory", "desc": "Checks for PowerShell PSReadLine history file",
        "bof": "pshistory", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "uacstatus", "desc": "Checks UAC status, integrity level, and local administrator group membership",
        "bof": "uacstatus", "module": "SAL-BOF", "args": []
    },
    {
        "cmd": "privcheck_all", "desc": "Run all privilege escalation checks sequentially",
        "bof": "privcheck_all", "module": "SAL-BOF", "args": []
    },

    # =========================================================================
    # SAR-BOF (sar.axs) - Situational Awareness Remote
    # =========================================================================
    {
        "cmd": "smartscan", "desc": "Smart port scan",
        "bof": "smartscan", "module": "SAR-BOF",
        "args": [
            ("target", "z", "IP address, range, or CIDR", False, None),
            ("scan_level", "i", "Scan level: 1=fast, 2=standard, 3=full, 0=custom", True, 2),
            ("custom_ports", "z", "Custom ports (e.g. 80,443,22-25)", True, ""),
        ]
    },
    {
        "cmd": "taskhound", "desc": "Collect scheduled tasks from remote systems",
        "bof": "taskhound", "module": "SAR-BOF",
        "args": [
            ("target", "z", "Remote system IP or hostname", False, None),
            ("username", "z", "Username for authentication", True, ""),
            ("password", "z", "Password for authentication", True, ""),
            ("save_directory", "z", "Directory to save XML files", True, ""),
            ("flags", "z", "Additional flags (-unsaved-creds, -grab-blobs)", True, ""),
        ]
    },
    {
        "cmd": "quser", "desc": "Query user sessions on a remote machine",
        "bof": "quser", "module": "SAR-BOF",
        "args": [("host", "z", "Remote host", True, "localhost")]
    },
    {
        "cmd": "nbtscan", "desc": "NetBIOS name scanner (nbtscan-like)",
        "bof": "nbtscan", "module": "SAR-BOF",
        "args": [
            ("target", "z", "IP address, range or CIDR", False, None),
            ("verbose", "i", "Verbose output (1=yes)", True, 0),
            ("quiet", "i", "Quiet output (1=yes)", True, 0),
            ("etc_hosts", "i", "etc_hosts format (1=yes)", True, 0),
            ("lmhosts", "i", "lmhosts format (1=yes)", True, 0),
            ("separator", "z", "Script-friendly separator", True, ""),
            ("timeout", "i", "Response timeout in ms", True, 1000),
        ]
    },

    # =========================================================================
    # Elevation-BOF (elevate.axs)
    # =========================================================================
    {
        "cmd": "getsystem_token", "desc": "Elevate to SYSTEM via token impersonation",
        "bof": "getsystem_token", "module": "Elevation-BOF", "args": []
    },
    {
        "cmd": "uac_sspi", "desc": "UAC bypass via SSPI Datagram Contexts - forges a token from fake network auth",
        "bof": "uac_sspi", "module": "Elevation-BOF",
        "args": [("path", "z", "Path to agent binary", False, None)]
    },
    {
        "cmd": "uac_regshellcmd", "desc": "UAC bypass via ms-settings Shell Open command registry key",
        "bof": "uac_regshellcmd", "module": "Elevation-BOF",
        "args": [("path", "z", "Path to agent binary", False, None)]
    },
    {
        "cmd": "DCOMPotato", "desc": "DCOMPotato - get SYSTEM via SeImpersonate privileges",
        "bof": "DCOMPotato", "module": "Elevation-BOF",
        "args": [
            ("use_token", "i", "Elevate current agent (1=token, 0=run program)", False, None),
            ("program", "Z", "Program to run in SYSTEM context (if use_token=0)", True, ""),
        ]
    },
    {
        "cmd": "printspoofer", "desc": "LPE via Print Spooler (Named Pipe Impersonation)",
        "bof": "printspoofer", "module": "Elevation-BOF",
        "args": [
            ("use_token", "i", "Elevate current agent (1=token, 0=run program)", False, None),
            ("program", "Z", "Program to run in SYSTEM context (if use_token=0)", True, ""),
        ]
    },

    # =========================================================================
    # Creds-BOF (creds.axs & submodules)
    # =========================================================================
    {
        "cmd": "askcreds", "desc": "Prompt for credentials via Windows UI",
        "bof": "askcreds", "module": "Creds-BOF",
        "args": [
            ("prompt", "Z", "Dialog title prompt", True, "Restore Network Connection"),
            ("note", "Z", "Dialog note text", True, "Please verify your Windows user credentials to proceed"),
            ("wait_time", "i", "Wait time in seconds", True, 30),
        ]
    },
    {
        "cmd": "cookie-monster", "desc": "Locate and copy cookie files for Edge/Chrome/Firefox",
        "bof": "cookie-monster-bof", "module": "Creds-BOF",
        "args": [
            ("browser", "z", "Browser: chrome, msedge, firefox, or all", True, ""),
            ("profile", "z", "Custom browser profile path", True, ""),
            ("browser_pid", "i", "Browser PID", True, 0),
            ("dump_cookie", "i", "Dump cookie file (1=yes)", True, 0),
            ("dump_password", "i", "Dump login data file (1=yes)", True, 0),
            ("dump_key", "i", "Dump encryption key (1=yes)", True, 0),
            ("cookie_pid", "i", "Cookie PID", True, 0),
            ("password_pid", "i", "Password PID", True, 0),
        ]
    },
    {
        "cmd": "get-netntlm", "desc": "Retrieve NetNTLM hash for the current user (Internal Monologue)",
        "bof": "get-netntlm", "module": "Creds-BOF",
        "args": [("no_ess", "i", "Disable session security for NetNTLMv1 (1=yes)", True, 0)]
    },
    {
        "cmd": "ek-hashdump", "desc": "Dump SAM hashes",
        "bof": "hashdump", "module": "Creds-BOF", "args": []
    },
    {
        "cmd": "lsadump_secrets", "desc": "Dump LSA secrets from SECURITY hive (requires SYSTEM)",
        "bof": "lsadump_secrets", "module": "Creds-BOF", "args": []
    },
    {
        "cmd": "lsadump_sam", "desc": "Dump SAM hashes via registry (requires admin)",
        "bof": "lsadump_sam", "module": "Creds-BOF", "args": []
    },
    {
        "cmd": "lsadump_cache", "desc": "Dump cached domain credentials (DCC2/MSCacheV2, requires SYSTEM)",
        "bof": "lsadump_cache", "module": "Creds-BOF", "args": []
    },
    {
        "cmd": "nanodump", "desc": "Use syscalls to dump LSASS",
        "bof": "nanodump", "module": "Creds-BOF",
        "args": [
            ("dump_path", "z", "Path where to write dump file", True, ""),
            ("write_file", "i", "Write to file (1=yes)", True, 0),
            ("use_valid_sig", "i", "Use valid signature (1=yes)", True, 0),
            ("fork", "i", "Fork target process (1=yes)", True, 0),
            ("snapshot", "i", "Snapshot process (1=yes)", True, 0),
            ("dup", "i", "Duplicate existing handle (1=yes)", True, 0),
            ("elevate_handle", "i", "Elevate handle (1=yes)", True, 0),
            ("duplicate_elevate", "i", "Duplicate elevate (1=yes)", True, 0),
            ("use_seclogon_leak_local", "i", "Seclogon leak local (1=yes)", True, 0),
            ("use_seclogon_leak_remote", "i", "Seclogon leak remote (1=yes)", True, 0),
            ("seclogon_leak_remote_binary", "z", "Seclogon leak remote binary path", True, ""),
            ("use_seclogon_duplicate", "i", "Seclogon duplicate (1=yes)", True, 0),
            ("spoof_callstack", "i", "Spoof callstack (1=yes)", True, 0),
            ("use_silent_process_exit", "i", "Silent process exit (1=yes)", True, 0),
            ("silent_process_exit", "z", "Silent process exit folder", True, ""),
            ("use_lsass_shtinkering", "i", "LSASS Shtinkering (1=yes)", True, 0),
            ("get_pid", "i", "Get PID only (1=yes)", True, 0),
            ("pid", "i", "Target LSASS PID", True, 0),
            ("chunk_size", "i", "Chunk size in bytes", True, 921600),
        ]
    },
    {
        "cmd": "underlaycopy", "desc": "Copy file using low-level NTFS access (MFT or Metadata mode)",
        "bof": "underlaycopy", "module": "Creds-BOF",
        "args": [
            ("mode", "z", "Copy mode: MFT or Metadata", False, None),
            ("source", "z", "Source file path", False, None),
            ("destination", "z", "Destination file path", True, ""),
            ("download", "i", "Download to server instead (1=yes)", True, 0),
        ]
    },

    # =========================================================================
    # Execution-BOF (execution.axs & submodules)
    # =========================================================================
    {
        "cmd": "ek-execute-assembly", "desc": "Perform in-process .NET assembly execution",
        "bof": "execute-assembly", "module": "Execution-BOF",
        "args": [
            ("assembly", "b", ".NET assembly file", False, None),
            ("params", "z", ".NET assembly parameters", True, ""),
        ]
    },
    {
        "cmd": "noconsolation", "desc": "Run unmanaged EXE/DLL inside agent memory",
        "bof": "NoConsolation", "module": "Execution-BOF",
        "args": [
            ("payload", "b", "EXE/DLL payload file", False, None),
            ("args", "z", "Arguments string", True, ""),
        ]
    },

    # =========================================================================
    # Injection-BOF (inject.axs)
    # =========================================================================
    {
        "cmd": "inject-cfg", "desc": "Inject shellcode via CFG overwrite (combase.dll __guard_check_icall_fptr)",
        "bof": "inject_cfg", "module": "Injection-BOF",
        "args": [
            ("pid", "i", "Target process ID", False, None),
            ("shellcode", "b", "Shellcode file", False, None),
        ]
    },
    {
        "cmd": "inject-sec", "desc": "Inject shellcode via section mapping",
        "bof": "inject_sec", "module": "Injection-BOF",
        "args": [
            ("pid", "i", "Target process ID", False, None),
            ("shellcode", "b", "Shellcode file", False, None),
        ]
    },
    {
        "cmd": "inject-poolparty", "desc": "Inject shellcode via Pool Party technique",
        "bof": "inject_poolparty", "module": "Injection-BOF",
        "args": [
            ("pid", "i", "Target process ID", False, None),
            ("shellcode", "b", "Shellcode file", False, None),
            ("technique", "i", "Technique variant (1-8)", False, None),
        ]
    },
    {
        "cmd": "inject-32to64", "desc": "Inject x64 shellcode from WOW64 (32-bit) into native 64-bit process",
        "bof": "inject_32to64", "module": "Injection-BOF",
        "args": [
            ("pid", "i", "Target process ID", False, None),
            ("shellcode", "b", "Shellcode file", False, None),
        ]
    },

    # =========================================================================
    # LateralMovement-BOF (lateral.axs)
    # =========================================================================
    {
        "cmd": "ek-psexec", "desc": "Spawn a session on a remote target via PsExec",
        "bof": "psexec", "module": "LateralMovement-BOF",
        "args": [
            ("target", "z", "Remote target IP or hostname", False, None),
            ("binary", "b", "Binary file to upload and execute", False, None),
            ("binary_name", "z", "Remote binary name", True, "random"),
            ("share", "z", "Share for copying the file", True, "ADMIN$"),
            ("svc_path", "z", "Path to the service file", True, "C:\\Windows"),
            ("svc_name", "z", "Service name", True, "random"),
            ("svc_description", "z", "Service description", True, "random"),
        ]
    },
    {
        "cmd": "ek-scshell", "desc": "Spawn a session on a remote target via SCShell",
        "bof": "scshell", "module": "LateralMovement-BOF",
        "args": [
            ("target", "z", "Remote target", False, None),
            ("svc_name", "z", "Service name to modify", True, "defragsvc"),
            ("remote_unc_path", "z", "Remote UNC path for binary", True, ""),
            ("binary", "b", "Binary file", False, None),
        ]
    },
    {
        "cmd": "ek-winrm", "desc": "Use WinRM to execute commands on other systems",
        "bof": "winrm", "module": "LateralMovement-BOF",
        "args": [
            ("target", "Z", "Remote target", False, None),
            ("cmd", "Z", "Command to execute", False, None),
            ("timeout", "i", "Timeout in ms (0=infinite)", True, 0),
            ("background", "i", "Keep WinRM shell open (1=yes)", True, 0),
            ("username", "Z", "Username (DOMAIN\\\\user)", True, ""),
            ("password", "Z", "Password", True, ""),
        ]
    },
    {
        "cmd": "token_make", "desc": "Creates an impersonated token from given credentials",
        "bof": "token_make", "module": "LateralMovement-BOF",
        "args": [
            ("username", "Z", "Username", False, None),
            ("password", "Z", "Password", False, None),
            ("domain", "Z", "Domain", False, None),
            ("type", "i", "Logon type (2=Interactive, 3=Network, 8=NetworkCleartext, 9=NewCredentials)", False, None),
        ]
    },
    {
        "cmd": "token_steal", "desc": "Steal access token from a process",
        "bof": "token_steal", "module": "LateralMovement-BOF",
        "args": [("pid", "i", "Process ID to steal token from", False, None)]
    },
    {
        "cmd": "runas-user", "desc": "Run a command as another user using explicit credentials",
        "bof": "runas", "module": "LateralMovement-BOF",
        "args": [
            ("username", "Z", "Username", False, None),
            ("password", "Z", "Password", False, None),
            ("domain", "Z", "Domain (use . for local)", False, None),
            ("command", "Z", "Command line to execute", False, None),
            ("logon_type", "i", "Logon type", True, 2),
            ("timeout", "i", "Timeout in ms (0=default 120000)", True, 0),
            ("no_output", "i", "Without output (1=no output)", True, 1),
            ("bypass_uac", "i", "Bypass UAC (1=yes)", True, 0),
        ]
    },
    {
        "cmd": "runas-session", "desc": "Execute binary in another users session via IHxHelpPaneServer COM",
        "bof": "runas_sess_ihxexec", "module": "LateralMovement-BOF",
        "args": [
            ("session_id", "i", "Target session ID", False, None),
            ("filepath", "Z", "File path to execute", False, None),
        ]
    },

    # =========================================================================
    # Postex-BOF (postex.axs)
    # =========================================================================
    {
        "cmd": "firewallrule_add", "desc": "Add a new inbound or outbound firewall rule using COM",
        "bof": "addfirewallrule", "module": "Postex-BOF",
        "args": [
            ("direction", "z", "Direction: in or out", True, "in"),
            ("port", "Z", "Port number", False, None),
            ("rulename", "Z", "Rule name", False, None),
            ("rulegroup", "Z", "Rule group", True, ""),
            ("description", "Z", "Rule description", True, ""),
        ]
    },
    {
        "cmd": "screenshot_bof", "desc": "Alternative screenshot capability (inline, no fork-n-run)",
        "bof": "Screenshot", "module": "Postex-BOF",
        "args": [
            ("note", "z", "Screenshot caption", True, "ScreenshotBOF"),
            ("pid", "i", "PID for window screenshot (0=full screen)", True, 0),
        ]
    },
    {
        "cmd": "sauroneye", "desc": "Search directories for files containing specific keywords (SauronEye BOF)",
        "bof": "sauroneye", "module": "Postex-BOF",
        "args": [
            ("cmdline", "z", "Full command line (for internal parsing)", True, ""),
            ("directories", "z", "Comma-separated directories to search", True, "C:\\"),
            ("filetypes", "z", "File extensions to search", True, ".txt,.docx"),
            ("keywords", "z", "Keywords (supports wildcards *)", True, ""),
            ("search_contents", "i", "Search file contents (1=yes)", True, 0),
            ("max_filesize", "i", "Max file size in KB", True, 1024),
            ("system_dirs", "i", "Include system directories (1=yes)", True, 0),
            ("before_date", "z", "Before date (dd.MM.yyyy)", True, ""),
            ("after_date", "z", "After date (dd.MM.yyyy)", True, ""),
            ("check_macro", "i", "Check VBA macros (1=yes)", True, 0),
            ("show_date", "i", "Show file dates (1=yes)", True, 0),
            ("wildcard_attempts", "i", "Max wildcard matching attempts", True, 1000),
            ("wildcard_size", "i", "Max wildcard search area KB", True, 200),
            ("wildcard_backtrack", "i", "Max backtracking operations", True, 1000),
        ]
    },

    # =========================================================================
    # Process-BOF (process.axs)
    # =========================================================================
    {
        "cmd": "findmodule", "desc": "Identify processes which have a certain module loaded",
        "bof": "findmodule", "module": "Process-BOF",
        "args": [("module", "Z", "Module name (e.g. clr.dll, amsi.dll)", False, None)]
    },
    {
        "cmd": "findprochandle", "desc": "Identify processes with a specific process handle in use",
        "bof": "findprochandle", "module": "Process-BOF",
        "args": [("proc", "Z", "Process name (e.g. lsass.exe)", False, None)]
    },
    {
        "cmd": "psc", "desc": "Shows processes with established TCP and RDP connections",
        "bof": "psc", "module": "Process-BOF", "args": []
    },
    {
        "cmd": "procfreeze_freeze", "desc": "Freeze a target process using PPL bypass via WerFaultSecure.exe",
        "bof": "procfreeze", "module": "Process-BOF",
        "args": [
            ("action", "i", "Action (1=freeze)", True, 1),
            ("pid", "i", "Process ID to freeze", False, None),
        ]
    },
    {
        "cmd": "procfreeze_unfreeze", "desc": "Unfreeze a previously frozen process",
        "bof": "procfreeze", "module": "Process-BOF",
        "args": [
            ("action", "i", "Action (2=unfreeze)", True, 2),
            ("pid", "i", "Unused (0)", True, 0),
        ]
    },

    # =========================================================================
    # AD-BOF (ad.axs & submodules)
    # =========================================================================
    {
        "cmd": "adwssearch", "desc": "Executes ADWS query",
        "bof": "adws_search", "module": "AD-BOF",
        "args": [
            ("query", "z", "ADWS query filter", False, None),
            ("attributes", "z", "Comma-separated attributes", True, ""),
            ("dc", "z", "Target domain controller", True, ""),
            ("dn", "z", "Custom base DN", True, ""),
        ]
    },
    {
        "cmd": "badtakeover", "desc": "Account takeover using the BadSuccessor technique",
        "bof": "badtakeover", "module": "AD-BOF",
        "args": [
            ("ou", "z", "Target OU to write malicious dMSA", False, None),
            ("account", "z", "Name of the new dMSA to create", False, None),
            ("sid", "z", "SID of your current context", False, None),
            ("dn", "z", "Target user objects DN", False, None),
            ("domain", "z", "Current domain", False, None),
        ]
    },
    {
        "cmd": "dcsync-single", "desc": "Perform DCSync on a single user",
        "bof": "dcsync-single", "module": "AD-BOF",
        "args": [
            ("target", "z", "Target username or DN", False, None),
            ("is_dn", "i", "Is distinguished name (1=yes)", True, 0),
            ("ou_path", "z", "OU path to search", True, ""),
            ("dc_address", "z", "Domain Controller address", True, ""),
            ("use_ldaps", "i", "Use LDAPS (1=yes)", True, 0),
            ("only_nt", "i", "Only NTLM hashes (1=yes)", True, 0),
        ]
    },
    {
        "cmd": "dcsync-all", "desc": "Perform DCSync for all users in the domain",
        "bof": "dcsync-all", "module": "AD-BOF",
        "args": [
            ("ou_path", "z", "OU path to search", True, ""),
            ("dc_address", "z", "Domain Controller address", True, ""),
            ("use_ldaps", "i", "Use LDAPS (1=yes)", True, 0),
            ("only_nt", "i", "Only NTLM hashes (1=yes)", True, 0),
            ("only_users", "i", "Only User and Trust accounts (1=yes)", True, 0),
        ]
    },
    {
        "cmd": "ek-ldapsearch", "desc": "Executes LDAP query",
        "bof": "ldapsearch", "module": "AD-BOF",
        "args": [
            ("query", "Z", "LDAP filter query", False, None),
            ("attributes", "z", "Attributes to retrieve", True, "*"),
            ("count", "i", "Result max size (0=unlimited)", True, 0),
            ("scope", "i", "Scope: 1=BASE, 2=LEVEL, 3=SUBTREE", True, 3),
            ("dc", "z", "DC hostname or IP", True, ""),
            ("dn", "z", "LDAP query base DN", True, ""),
            ("ldaps", "i", "Use LDAPS (1=yes)", True, 0),
        ]
    },
    {
        "cmd": "readlaps", "desc": "Read LAPS password for a computer",
        "bof": "readlaps", "module": "AD-BOF",
        "args": [
            ("dc", "z", "Target domain controller", True, ""),
            ("dn", "z", "Root DN", True, ""),
            ("searchFilter", "z", "LDAP search filter", True, ""),
            ("reportTarget", "z", "Target computer name", True, ""),
        ]
    },
    {
        "cmd": "webdav_enable", "desc": "Enable the WebDAV client service without elevated permissions",
        "bof": "webdav_enable", "module": "AD-BOF", "args": []
    },
    {
        "cmd": "webdav_status", "desc": "Determine if WebDAV is running on a remote system",
        "bof": "webdav_status", "module": "AD-BOF",
        "args": [("hosts", "z", "Comma-separated hosts to check", True, "127.0.0.1")]
    },
]


def find_bof_binaries(cmd_def):
    """Find compiled .o binaries for a command across the Extension-Kit repository."""
    module_dir = EXTENSION_KIT_DIR / cmd_def["module"]
    bof_name = cmd_def["bof"]

    found_files = {}

    for root, dirs, files in os.walk(module_dir):
        for f in files:
            if not f.endswith(".o"):
                continue
            path = Path(root) / f
            # Match 64-bit: e.g. bof.x64.o, bof.x86_64.o
            if f.lower() == f"{bof_name.lower()}.x64.o" or f.lower() == f"{bof_name.lower()}.x86_64.o":
                found_files["amd64"] = path
            # Match 32-bit: e.g. bof.x32.o, bof.x86.o, bof.i386.o
            elif f.lower() == f"{bof_name.lower()}.x32.o" or f.lower() == f"{bof_name.lower()}.x86.o" or f.lower() == f"{bof_name.lower()}.i386.o":
                found_files["386"] = path

    return found_files


def copy_and_generate_files(cmd_def, dest_dir):
    """Copy binaries and return list of file definitions for extension.json."""
    found_binaries = find_bof_binaries(cmd_def)
    bof_name = cmd_def["bof"]

    file_entries = []

    if "amd64" in found_binaries:
        src = found_binaries["amd64"]
        dst_name = f"{bof_name}.x64.o"
        shutil.copy2(src, dest_dir / dst_name)
        file_entries.append({
            "os": "windows",
            "arch": "amd64",
            "path": dst_name,
        })

    if "386" in found_binaries:
        src = found_binaries["386"]
        dst_name = f"{bof_name}.x86.o"
        shutil.copy2(src, dest_dir / dst_name)
        file_entries.append({
            "os": "windows",
            "arch": "386",
            "path": dst_name,
        })

    return file_entries


def generate_extension_json(cmd_def, file_entries):
    """Generate a Forge-compatible extension.json."""
    args = []
    for arg_tuple in cmd_def.get("args", []):
        name, arg_type, desc, optional = arg_tuple[0], arg_tuple[1], arg_tuple[2], arg_tuple[3]
        default = arg_tuple[4] if len(arg_tuple) > 4 else None
        entry = {
            "name": name,
            "desc": desc,
            "type": arg_type,
            "optional": optional,
        }
        if default is not None:
            entry["default"] = default
        args.append(entry)

    # Fallback if no files were found
    if not file_entries:
        file_entries = [
            {"os": "windows", "arch": "amd64", "path": f"{cmd_def['bof']}.x64.o"},
            {"os": "windows", "arch": "386", "path": f"{cmd_def['bof']}.x86.o"},
        ]

    return {
        "command_name": cmd_def["cmd"],
        "help": cmd_def["desc"],
        "extension_author": "Adaptix-Framework",
        "original_author": "Adaptix-Framework",
        "repo_url": "https://github.com/Adaptix-Framework/Extension-Kit",
        "version": "1.0.0",
        "entrypoint": "go",
        "files": file_entries,
        "arguments": args,
    }


def main():
    print("=" * 60)
    print("Extension-Kit -> Forge Integration Generator")
    print("=" * 60)

    FORGE_COLLECTIONS_DIR.mkdir(parents=True, exist_ok=True)

    sources = []
    total_commands = 0
    total_with_files = 0

    for cmd_def in COMMANDS:
        cmd_name = cmd_def["cmd"]
        cmd_dir = FORGE_COLLECTIONS_DIR / cmd_name
        cmd_dir.mkdir(parents=True, exist_ok=True)

        # Copy binaries and get file entries
        file_entries = copy_and_generate_files(cmd_def, cmd_dir)

        # Generate extension.json
        ext_json = generate_extension_json(cmd_def, file_entries)
        ext_path = cmd_dir / "extension.json"
        with open(ext_path, "w") as f:
            json.dump(ext_json, f, indent=2)

        status = f"✓ ({len(file_entries)} archs)" if file_entries else "○ (no .o files)"
        if file_entries:
            total_with_files += 1

        arg_summary = ", ".join(f"{a[0]}:{a[1]}" for a in cmd_def.get("args", []))
        print(f"  [{cmd_def['module']:20s}] {cmd_name:25s} [{arg_summary or 'no args':40s}] {status}")

        sources.append({
            "name": cmd_name,
            "command_name": cmd_name,
            "description": cmd_def["desc"],
            "repo_url": "",
            "custom_download_url": "",
        })
        total_commands += 1

    # Write ExtensionKit_sources.json
    sources_path = FORGE_BASE_DIR / "ExtensionKit_sources.json"
    with open(sources_path, "w") as f:
        json.dump(sources, f, indent="\t")
    print(f"\n✓ Wrote {sources_path} ({total_commands} commands)")

    # Update collection_sources.json
    cs_path = FORGE_BASE_DIR / "collection_sources.json"
    with open(cs_path, "r") as f:
        cs = json.load(f)
    if not any(s["name"] == "ExtensionKit" for s in cs):
        cs.append({"name": "ExtensionKit", "type": "bof"})
        with open(cs_path, "w") as f:
            json.dump(cs, f, indent="\t")
        print(f"✓ Added ExtensionKit to {cs_path}")
    else:
        print(f"○ ExtensionKit already in {cs_path}")

    # Create empty commands file
    cmds_path = FORGE_BASE_DIR / "ExtensionKit_commands.json"
    if not cmds_path.exists():
        with open(cmds_path, "w") as f:
            json.dump([], f)
        print(f"✓ Created empty {cmds_path}")

    print(f"\n{'=' * 60}")
    print(f"Total commands: {total_commands}")
    print(f"Commands with .o files: {total_with_files}")
    print(f"Commands needing build: {total_commands - total_with_files}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
