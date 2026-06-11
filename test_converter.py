title: LSASS Memory Dump via Common Tools
id: a1b2c3d4-0002-4000-8000-000000000002
status: experimental
description: Detects attempts to dump LSASS memory using common tools like procdump, mimikatz or taskmgr. Credential dumping from LSASS is a common post-exploitation technique.
author: Jean Fogaca
date: 2024/01/01
tags:
  - attack.credential_access
  - attack.t1003.001
level: critical
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection_tools:
    Image|endswith:
      - '\procdump.exe'
      - '\procdump64.exe'
    CommandLine|contains: 'lsass'
  selection_mimikatz:
    CommandLine|contains:
      - 'sekurlsa'
      - 'lsadump'
  condition: selection_tools or selection_mimikatz
falsepositives:
  - Legitimate memory analysis by security tools
  - Authorized forensic investigation
