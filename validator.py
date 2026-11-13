"""Stage 4: prove a finding by writing a Foundry exploit and running it."""
import re
import shutil
import subprocess
from pathlib import Path

from llm import ask

WRITER = """You are an exploit developer. Write a Foundry test that PROVES the
vulnerability described below by actually performing the attack.

Strict rules:
- Start with: // SPDX-License-Identifier: MIT and pragma solidity ^0.8.20;
- import {Test} from "forge-std/Test.sol"; and import "./Target.sol";
- One contract named ExploitTest that inherits Test, with one function test_Exploit().
- Deploy the target contracts yourself and fund them realistically with vm.deal or
  constructor value. If the attack needs an attacker contract, define it in the same file.
- The attacker must be a separate address from the deployer (use makeAddr and vm.prank).
- Never give the attacker funds or permissions the contract would not give them.
- End with assertions that PROVE the impact, for example the attacker balance went up,
  the attacker became owner, or debt exceeds what honest collateral allows.
  If the attack does not work, the test MUST fail. No try/catch.
Reply with ONLY the Solidity code in one ```solidity block."""

LOCAL_IMPORT = re.compile(r"^\s*import\s+[^;]*\"\./[^\"]*\";\s*$", re.M)


def extract_code(text):
    match = re.search(r"```(?:solidity)?\s*\n(.*?)```", text, re.S)
    return (match.group(1) if match else text).strip() + "\n"


def run_forge(project, test_file):
    result = subprocess.run(
        ["forge", "test", "--match-path", str(test_file), "-vv"],
        cwd=project, capture_output=True, text=True, timeout=600,
    )
    output = result.stdout + result.stderr
    passed = result.returncode == 0 and "[PASS]" in output
    return passed, output[-3000:]


def validate(name, source, ruling, project, attempts=2):
    """Try to prove a VULNERABLE verdict. Returns a dict with the outcome."""
    project = Path(project)
    folder = project / "test" / "generated" / name
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir(parents=True)

    # The exploit targets the same scrubbed code the agents judged
    (folder / "Target.sol").write_text(LOCAL_IMPORT.sub("", source))
    test_file = folder / "Exploit.t.sol"
    rel_test = test_file.relative_to(project)

    prompt = (
        "TARGET CODE (saved as ./Target.sol):\n" + source
        + "\n\nVULNERABILITY: " + str(ruling.get("vulnerability_type"))
        + "\nROOT CAUSE: " + str(ruling.get("root_cause"))
        + "\n\nATTACK PLAN FROM THE RED TEAM:\n" + ruling.get("attack", "")
    )

    log = ""
    for attempt in range(1, attempts + 1):
        if attempt > 1:
            prompt += "\n\nYOUR PREVIOUS TEST FAILED WITH THIS OUTPUT. Fix it:\n" + log
        test_file.write_text(extract_code(ask(WRITER, prompt)))
        passed, log = run_forge(project, rel_test)
        if passed:
            return {"validated": True, "attempts": attempt, "exploit_file": str(rel_test),
                    "exploit_code": test_file.read_text(), "log": log}

    # Remove failed exploits so they do not break later compiles
    code = test_file.read_text()
    shutil.rmtree(folder)
    return {"validated": False, "attempts": attempts, "exploit_file": None,
            "exploit_code": code, "log": log}
