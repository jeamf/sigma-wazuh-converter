# sigma-wazuh-converter

Convert [Sigma](https://github.com/SigmaHQ/sigma) detection rules to [Wazuh](https://wazuh.com/) custom rules (XML) — bridging the gap where no official backend exists.

> **Why this exists:** Wazuh has no native Sigma support and no official pySigma backend. This tool provides a practical conversion pipeline so detection engineers can write rules once in the vendor-agnostic Sigma format and deploy them directly in Wazuh.

---

## How it works

```
Sigma Rule (.yml)  →  [converter]  →  Wazuh Custom Rule (.xml)
```

The converter:
- Parses the Sigma YAML structure (detection, logsource, tags, level)
- Maps Sigma field names to Wazuh field names
- Translates detection conditions to Wazuh `<field>` elements with pcre2 patterns
- Maps Sigma severity levels to Wazuh rule levels
- Extracts MITRE ATT&CK tags and adds them as Wazuh groups

---

## Installation

```bash
git clone https://github.com/jeamf/sigma-wazuh-converter
cd sigma-wazuh-converter
pip install -r requirements.txt
```

---

## Usage

**Convert a single rule:**
```bash
python src/converter.py rules/examples/suspicious_encoded_powershell.yml output/rule.xml
```

**Convert an entire directory:**
```bash
python src/converter.py rules/ output/ --start-id 100001
```

**Output example** — input Sigma rule:
```yaml
title: Suspicious Encoded PowerShell Command
level: high
tags:
  - attack.execution
  - attack.t1059.001
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
  condition: selection
```

Generated Wazuh rule:
```xml
<group name="sigma,">
  <rule id="100001" level="12">
    <description>Suspicious Encoded PowerShell Command</description>
    <group>attack.execution,attack.T1059.001</group>
    <field name="win.eventdata.image" type="pcre2">\\powershell\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">\-EncodedCommand</field>
    <field name="win.eventdata.commandLine" type="pcre2">\-enc\ </field>
  </rule>
</group>
```

---

## Severity mapping

| Sigma level   | Wazuh level |
|---------------|-------------|
| informational | 3           |
| low           | 5           |
| medium        | 10          |
| high          | 12          |
| critical      | 15          |

---

## Deploying to Wazuh

1. Copy the generated XML file to your Wazuh manager:
```bash
scp output/rule.xml wazuh-manager:/var/ossec/etc/rules/sigma_rules.xml
```

2. Restart the Wazuh manager:
```bash
sudo systemctl restart wazuh-manager
```

3. Test with `wazuh-logtest`:
```bash
/var/ossec/bin/wazuh-logtest
```

---

## Running tests

```bash
pytest tests/ -v
```

---

## Roadmap

- [ ] Batch conversion with collision detection for rule IDs
- [ ] `if_sid` mapping per log source (scoping rules to correct decoder)
- [ ] Support for Sigma `near` and pipe conditions
- [ ] CI/CD pipeline with GitHub Actions
- [ ] Validation report (unsupported fields / conditions)

---

## Related work

- [SigmaHQ/pySigma](https://github.com/SigmaHQ/sigma) — official Sigma Python library
- [Wazuh custom rules documentation](https://documentation.wazuh.com/current/user-manual/ruleset/custom.html)
- [pySigma Wazuh backend discussion](https://github.com/SigmaHQ/pySigma-plugin-directory/discussions/52)

---

## Author

**Jean Fogaça** — Cybersecurity Analyst | SOC · SIEM · Incident Response  
[linkedin.com/in/jean-fogaca](https://linkedin.com/in/jean-fogaca)

---

## License

MIT
