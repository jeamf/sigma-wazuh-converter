"""
sigma_to_wazuh.py
Converts Sigma detection rules (YAML) to Wazuh custom rules (XML).
"""

import yaml
import xml.etree.ElementTree as ET
from xml.dom import minidom
import re
import sys
from pathlib import Path

# Sigma field → Wazuh field mapping
FIELD_MAP = {
    "CommandLine":     "win.eventdata.commandLine",
    "Image":           "win.eventdata.image",
    "ParentImage":     "win.eventdata.parentImage",
    "SourceIp":        "data.srcip",
    "DestinationIp":   "data.dstip",
    "EventID":         "win.system.eventID",
    "User":            "win.system.securityUserId",
    "TargetUsername":  "win.eventdata.targetUserName",
    "SubjectUsername": "win.eventdata.subjectUserName",
    "ObjectName":      "win.eventdata.objectName",
    "ProcessName":     "win.eventdata.processName",
    "FileName":        "win.eventdata.fileName",
    "ServiceName":     "win.eventdata.serviceName",
    "RegistryKey":     "win.eventdata.objectName",
    "Hashes":          "win.eventdata.hashes",
    "DestinationPort": "data.dstport",
    "SourcePort":      "data.srcport",
    "Initiated":       "win.eventdata.initiated",
    "Protocol":        "data.protocol",
}

# MITRE ATT&CK → Wazuh group prefix
MITRE_GROUP_PREFIX = "attack,"

# Severity mapping: Sigma level → Wazuh rule level
LEVEL_MAP = {
    "informational": 3,
    "low":           5,
    "medium":        10,
    "high":          12,
    "critical":      15,
}


def load_sigma(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def map_field(field: str) -> str:
    return FIELD_MAP.get(field, field.lower())


def build_condition(detection: dict) -> list:
    """
    Parse Sigma detection block and return list of (wazuh_field, value, negate) tuples.
    Supports basic selection with keywords, lists, and startswith/endswith/contains modifiers.
    """
    conditions = []
    for key, val in detection.items():
        if key == "condition":
            continue
        if isinstance(val, dict):
            for field, patterns in val.items():
                negate = field.startswith("|")
                clean_field = field.lstrip("|")

                # Handle modifiers (contains, startswith, endswith)
                if "|" in clean_field:
                    parts = clean_field.split("|")
                    raw_field = parts[0]
                    modifier = parts[1] if len(parts) > 1 else ""
                else:
                    raw_field = clean_field
                    modifier = ""

                wazuh_field = map_field(raw_field)

                if isinstance(patterns, list):
                    for p in patterns:
                        conditions.append((wazuh_field, str(p), modifier, negate))
                else:
                    conditions.append((wazuh_field, str(patterns), modifier, negate))

        elif isinstance(val, list):
            # keyword list
            for item in val:
                conditions.append(("full_log", str(item), "contains", False))
    return conditions


def build_mitre_groups(tags: list) -> str:
    groups = []
    for tag in tags:
        if tag.startswith("attack.t"):
            tid = tag.replace("attack.", "").upper()
            groups.append(f"attack.{tid}")
        elif tag.startswith("attack."):
            tactic = tag.replace("attack.", "").replace("_", "-")
            groups.append(f"attack.{tactic}")
    return ",".join(groups) if groups else ""


def sigma_to_wazuh_xml(sigma: dict, rule_id: int = 100001) -> str:
    title       = sigma.get("title", "Sigma Rule")
    description = sigma.get("description", title)
    level_str   = sigma.get("level", "medium").lower()
    tags        = sigma.get("tags", [])
    detection   = sigma.get("detection", {})

    wazuh_level = LEVEL_MAP.get(level_str, 10)
    mitre_groups = build_mitre_groups(tags)

    # Root group element
    group_el = ET.Element("group", name="sigma,")

    rule_el = ET.SubElement(group_el, "rule", id=str(rule_id), level=str(wazuh_level))

    # Description
    desc_el = ET.SubElement(rule_el, "description")
    desc_el.text = title

    # Info / full description
    if description and description != title:
        info_el = ET.SubElement(rule_el, "info", type="text")
        info_el.text = description

    # MITRE groups
    if mitre_groups:
        group2_el = ET.SubElement(rule_el, "group")
        group2_el.text = mitre_groups

    # Detection conditions
    conditions = build_condition(detection)
    for wazuh_field, value, modifier, negate in conditions:
        tag = "field" if wazuh_field != "full_log" else "match"
        attribs = {"name": wazuh_field} if tag == "field" else {}

        if modifier == "contains":
            attribs["type"] = "pcre2"
            pattern = re.escape(value)
        elif modifier == "startswith":
            attribs["type"] = "pcre2"
            pattern = "^" + re.escape(value)
        elif modifier == "endswith":
            attribs["type"] = "pcre2"
            pattern = re.escape(value) + "$"
        else:
            attribs["type"] = "pcre2"
            pattern = re.escape(value)

        if negate:
            attribs["negate"] = "yes"

        cond_el = ET.SubElement(rule_el, tag, **attribs)
        cond_el.text = pattern

    # Pretty print
    raw = ET.tostring(group_el, encoding="unicode")
    pretty = minidom.parseString(raw).toprettyxml(indent="  ")
    # Remove the xml declaration line
    lines = pretty.split("\n")[1:]
    return "\n".join(lines)


def convert_file(input_path: str, output_path: str, rule_id: int = 100001):
    sigma = load_sigma(input_path)
    xml_output = sigma_to_wazuh_xml(sigma, rule_id=rule_id)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(xml_output)
    print(f"[OK] {input_path} → {output_path} (rule_id={rule_id}, level={LEVEL_MAP.get(sigma.get('level','medium'),10)})")


def convert_directory(input_dir: str, output_dir: str, start_id: int = 100001):
    input_path  = Path(input_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    rule_id = start_id
    converted = 0
    errors = 0

    for sigma_file in sorted(input_path.glob("**/*.yml")):
        out_file = output_path / (sigma_file.stem + ".xml")
        try:
            convert_file(str(sigma_file), str(out_file), rule_id=rule_id)
            rule_id += 1
            converted += 1
        except Exception as e:
            print(f"[ERR] {sigma_file}: {e}")
            errors += 1

    print(f"\nDone: {converted} converted, {errors} errors. IDs: {start_id}–{rule_id - 1}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Convert Sigma rules (.yml) to Wazuh custom rules (.xml)"
    )
    parser.add_argument("input",  help="Sigma rule file (.yml) or directory")
    parser.add_argument("output", help="Output file (.xml) or directory")
    parser.add_argument("--start-id", type=int, default=100001,
                        help="Starting Wazuh rule ID (default: 100001)")
    args = parser.parse_args()

    inp = Path(args.input)
    if inp.is_dir():
        convert_directory(args.input, args.output, start_id=args.start_id)
    else:
        convert_file(args.input, args.output, rule_id=args.start_id)
