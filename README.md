# DM-REVERT-GRABBER-TOOL

🚀 Features

✅ Administrator Privilege Check - Ensures proper permissions before running
📦 Multiple Config Formats - Supports JSON, plain text, and direct reg add commands
🔍 Config Validation - Detects errors, duplicates, and sensitive paths
📊 Progress Tracking - Visual progress bar with detailed logging
🔄 Automatic Revert Scripts - Generates both .bat and .ps1 revert scripts
📝 Comprehensive Logging - Detailed logs for troubleshooting
🎯 Smart Parsing - Handles powercfg and netsh commands
💾 Multiple Output Formats - Text, JSON, and executable scripts

📋 Requirements

Windows 10/11
.NET 6.0 or higher
Administrator privileges

---------- 

📝 Configuration Formats
The tool supports multiple configuration formats. Choose the one that works best for your workflow.
Format 1: JSON Configuration
Create a file named registry_paths.json:
json{
  "registryEntries": [
    {
      "category": "Windows Updates",
      "path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate",
      "value": "WUServer",
      "type": "REG_SZ"
    },
    {
      "category": "Telemetry",
      "path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
      "value": "AllowTelemetry",
      "type": "REG_DWORD"
    },
    {
      "category": "Network",
      "path": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
      "value": "TcpAckFrequency",
      "type": "REG_DWORD"
    }
  ]
}


-------- 

Format 2: Reg Commands (Recommended)
Create a file named tweaks.txt and paste your reg add commands directly:


[Windows Updates]
reg add ( excecute command )

[Telemetry & Privacy]
reg add ( excecute command )


[Network Tweaks]
reg add ( excecute command )


[Visual Effects]
reg add ( excecute command )


[Power Settings]
reg add ( excecute command )


[Network Advanced]
reg add ( excecute command )

[Windows Updates]
reg add ( excecute command )


[Telemetry]
reg add ( excecute command )

[Network]
reg add ( excecute command )
---------------

📤 Output Files
After running, the tool generates:
| File Name                              | Description                                  |
| -------------------------------------- | -------------------------------------------- |
| `registry_backup_YYYYMMDD_HHMMSS.txt`  | Human-readable backup of all values          |
| `registry_backup_YYYYMMDD_HHMMSS.json` | JSON format backup for automation            |
| `revert_script_YYYYMMDD_HHMMSS.bat`    | Batch script to restore original values      |
| `revert_script_YYYYMMDD_HHMMSS.ps1`    | PowerShell script to restore original values |
| `default_values_YYYYMMDD_HHMMSS.txt`   | Registry commands with original values       |
| `backup_log_YYYYMMDD_HHMMSS.txt`       | Detailed execution log                       |

-----------------

🛡️ Safety Features
Validation Warnings
The tool warns you about:

✅ Invalid registry paths
✅ Duplicate entries
✅ Sensitive system paths (SAM, SECURITY)
✅ Critical security locations (Winlogon)
✅ Unknown registry types
✅ Empty paths or value names

What Gets Backed Up

✅ Current registry value
✅ Value type (REG_DWORD, REG_SZ, etc.)
✅ Whether value exists
✅ Timestamp of backup
✅ Error details if backup fails


