# Detection Card — T1053.005 Scheduled Task

## Overview
| Field | Value |
|-------|-------|
| Technique ID | T1053.005 |
| Name | Scheduled Task/Job: Scheduled Task |
| Tactic | Persistence, Execution |
| Severity | HIGH |
| False Positive Risk | MEDIUM |
| Data Sources | Security Log (EID 4698), Task Scheduler Operational (EID 106), Sysmon (EID 1) |

## What Are We Detecting?
Creation of Windows scheduled tasks using `schtasks.exe /create` with suspicious arguments — specifically tasks that execute from temp directories, invoke PowerShell/cmd, or run as SYSTEM. This is one of the most common persistence mechanisms used by adversaries.

## Expected Windows Event IDs
| Event ID | Channel | Field of Interest | What It Shows |
|----------|---------|-------------------|---------------|
| 4698 | Security | TaskContent (XML), SubjectUserName | New scheduled task registered with full XML definition |
| 106 | Task Scheduler Operational | TaskName | Task registered in Task Scheduler |
| 200 | Task Scheduler Operational | ActionName | Task action started |
| 1 (Sysmon) | Sysmon Operational | CommandLine, ParentImage | schtasks.exe process creation with arguments |

## Sigma Rules Applied
- `scheduled_task_creation.yml` — Detects schtasks.exe /create with suspicious arguments

## Detection Logic
```
IF process_name ENDS_WITH "schtasks.exe"
  AND command_line CONTAINS "/create"
  AND command_line CONTAINS any of:
    ["\AppData\Local\Temp", "\Users\Public", "powershell",
     "cmd.exe /c", "mshta", "wscript", "SYSTEM"]
THEN → ALERT: Suspicious Scheduled Task Creation (HIGH)
```

## Atomic Red Team Test
- **T1053.005 Test #1**: Scheduled Task Startup Script — Creates a task triggered at system startup
- **T1053.005 Test #2**: Scheduled Task At Logon — Creates persistence via logon trigger
- **T1053.005 Test #4**: PowerShell Scheduled Task — Creates task with PowerShell action

## Evasion Variants to Know
1. **COM-based task creation**: Using Task Scheduler COM API instead of schtasks.exe to avoid command-line logging
2. **XML import**: `schtasks /create /xml task.xml` hides the action from the command line
3. **Remote task creation**: `schtasks /create /S remote_host` creates tasks on other systems
4. **Renamed binary**: Copying schtasks.exe to another name to avoid process name detection
5. **WMI-based scheduling**: Using WMI event subscriptions instead of Task Scheduler

## Known Threat Groups
APT29, FIN7, Lazarus Group, Wizard Spider, Sandworm Team, APT28, OilRig

## References
- [MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/)
- [Atomic Red Team T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md)
