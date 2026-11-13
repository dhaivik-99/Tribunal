"""Stage 2 and 3: attacker and defender agents debate, a judge rules."""
import json

from llm import ask

ATTACKER = """You are an offensive smart contract security researcher.
Find the single most serious vulnerability that lets an attacker steal funds,
take control, or break the core accounting of this contract.
Think about reentrancy, access control, signature replay, oracle and price
manipulation, unsafe defaults and initialization, and business logic flaws.
Static analyzer hints are included but are noisy and incomplete; do not rely on them.
Describe the concrete attack step by step: who calls what, in what order, and what they gain.
If you honestly cannot find an exploitable issue, reply with exactly: NONE"""

DEFENDER = """You are a senior smart contract auditor reviewing a claimed vulnerability.
Your job is to challenge it. Explain precisely why the attack would fail, needs
unrealistic conditions, or is overstated. Point to the specific lines that stop it.
Be honest: if the attack really works, say so plainly and concede."""

JUDGE = """You are the lead auditor. You have read the contract, the attacker claim
and the defender rebuttal. Decide whether the contract has a real, exploitable
vulnerability. Ignore style issues, gas optimizations and low-impact warnings.
Respond with ONLY a JSON object, no other text:
{"verdict": "VULNERABLE" or "SAFE",
 "vulnerability_type": "short name, or none",
 "severity": "Critical, High, Medium, Low or None",
 "root_cause": "one or two sentences",
 "confidence": a number from 0 to 1}"""


SCOPE = """AUDIT SCOPE AND TRUST ASSUMPTIONS:
These are simplified contracts. Token transfers in deposit functions are
intentionally omitted; treat deposited collateral as real. Addresses set by the
deployer (owner, signer, price feed admin) are trusted and act honestly.
Only report issues an outside attacker can exploit."""


def parse_json(text):
    start, end = text.find("{"), text.rfind("}")
    return json.loads(text[start:end + 1])


def debate(source, hints):
    """Run attacker, defender and judge on one contract."""
    context = SCOPE + "\n\nCONTRACT:\n" + source + "\n\nSTATIC ANALYZER HINTS:\n" + (hints or "none")

    attack = ask(ATTACKER, context)
    if attack.strip() == "NONE":
        defense = "The attacker found nothing to rebut."
    else:
        defense = ask(DEFENDER, context + "\n\nATTACKER CLAIM:\n" + attack)

    ruling_text = ask(
        JUDGE,
        context + "\n\nATTACKER CLAIM:\n" + attack + "\n\nDEFENDER REBUTTAL:\n" + defense,
    )
    ruling = parse_json(ruling_text)
    ruling["attack"] = attack
    ruling["defense"] = defense
    return ruling
