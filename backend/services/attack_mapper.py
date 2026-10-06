"""Conservative ATT&CK mapping: requires behavior context, not merely an IOC."""
from __future__ import annotations

# Technique names/IDs below are established MITRE ATT&CK Enterprise entries.
# We deliberately do not infer a technique from an IP/domain/hash alone.
BEHAVIOR_MAPPINGS = (
    {
        "needles": ("phishing", "credential-lure", "simulated lure email", "suspicious email lure"),
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique": "Phishing",
        "technique_id": "T1566",
        "rationale": "Synthetic observations explicitly describe a phishing/lure behavior.",
    },
    {
        "needles": ("repeated authentication failures", "password spraying", "brute-force behavior"),
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "rationale": "Synthetic telemetry explicitly describes repeated authentication attempts.",
    },
    {
        "needles": ("simulated mass file-change", "file-encryption behavior observed", "ransomware impact simulation"),
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique": "Data Encrypted for Impact",
        "technique_id": "T1486",
        "rationale": "The record describes simulated endpoint impact behavior; no code is executed.",
    },
)


def map_behavior_to_attack(category: str | None, description: str | None) -> dict | None:
    text = f"{category or ''} {description or ''}".casefold()
    for mapping in BEHAVIOR_MAPPINGS:
        if any(needle in text for needle in mapping["needles"]):
            return {key: value for key, value in mapping.items() if key != "needles"}
    return None
