title: Suspicious Encoded PowerShell Command
id: a1b2c3d4-0001-4000-8000-000000000001
status: experimental
description: Detects execution of PowerShell with encoded command arguments, a common technique used by attackers to obfuscate malicious scripts.
author: Jean Fogaca
date: 2024/01/01
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
level: high
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
      - '-ec '
      - 'FromBase64String'
  condition: selection
falsepositives:
  - Legitimate administrative scripts using encoded commands
  - Software installers
