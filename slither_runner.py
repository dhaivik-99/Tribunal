"""Step 1: run Slither on a Foundry project and return clean findings."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run_slither(project_path):
    """Run Slither and return its findings as a list of dicts."""
    out_file = Path(tempfile.mkdtemp()) / "slither.json"
    subprocess.run(
        ["slither", str(project_path), "--json", str(out_file), "--filter-paths", "lib|test"],
        capture_output=True,
        text=True,
    )
    if not out_file.exists():
        sys.exit("Slither produced no output. Run it by hand to see the error.")

    data = json.loads(out_file.read_text())
    findings = []
    for d in data.get("results", {}).get("detectors", []):
        elements = d.get("elements", [])
        location = elements[0]["source_mapping"] if elements else {}
        findings.append({
            "check": d["check"],
            "impact": d["impact"],
            "confidence": d["confidence"],
            "file": location.get("filename_relative", "?"),
            "lines": location.get("lines", []),
            "description": d["description"].strip(),
        })
    return findings


if __name__ == "__main__":
    project = sys.argv[1] if len(sys.argv) > 1 else "../web3-attack-pocs"
    findings = run_slither(project)
    print("Slither found {} candidate issues\n".format(len(findings)))
    for f in findings:
        print("[{}] {}  ->  {}".format(f["impact"], f["check"], f["file"]))
