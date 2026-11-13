"""Run the full Tribunal pipeline on the Project 1 contracts and score it."""
import json
import re
import sys
from pathlib import Path

from agents import debate
from slither_runner import run_slither
from validator import validate


def scrub(text):
    """Hide the answer key: remove comments and the Vulnerable / Fixed prefixes."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r"\b(Vulnerable|Fixed)(?=[A-Z])", "", text)
    return text


def score(results, key):
    tp = sum(r[key] == "VULNERABLE" and r["truth"] == "VULNERABLE" for r in results)
    fp = sum(r[key] == "VULNERABLE" and r["truth"] == "SAFE" for r in results)
    fn = sum(r[key] == "SAFE" and r["truth"] == "VULNERABLE" for r in results)
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    return "caught {} of {} real bugs, {} false alarms  (precision {:.0%}, recall {:.0%})".format(
        tp, tp + fn, fp, precision, recall)


def main(project, run_validation=True):
    project = Path(project)
    findings = run_slither(project)

    targets = sorted(
        p for p in (project / "src").rglob("*.sol")
        if p.name.startswith("Vulnerable") or p.name.startswith("Fixed")
    )

    results = []
    for path in targets:
        truth = "VULNERABLE" if path.name.startswith("Vulnerable") else "SAFE"
        hints = "\n".join(
            scrub("[{}] {}: {}".format(f["impact"], f["check"], f["description"]))
            for f in findings
            if f["file"].endswith(path.name)
        )
        source = path.read_text()
        # Add files this contract imports (for example SimplePool.sol)
        for dep in list(path.parent.glob("*.sol")):
            if dep.name != path.name and dep.name in source:
                source += "\n\n" + dep.read_text()
        source = scrub(source)

        print("Judging {} ...".format(path.name), flush=True)
        ruling = debate(source, hints)
        ruling["file"] = path.name
        ruling["truth"] = truth
        ruling["final"] = ruling["verdict"]

        if run_validation and ruling["verdict"] == "VULNERABLE":
            print("  writing and running an exploit ...", flush=True)
            proof = validate("case_{:02d}".format(len(results)), source, ruling, project)
            ruling["validation"] = proof
            # Only a working exploit keeps the VULNERABLE verdict
            ruling["final"] = "VULNERABLE" if proof["validated"] else "SAFE"

        results.append(ruling)
        status = "OK " if ruling["final"] == truth else "XX "
        extra = ""
        if "validation" in ruling:
            extra = "  [exploit {}]".format("PASSED" if ruling["validation"]["validated"] else "failed")
        print("  {}{} (truth {}) - {}{}".format(
            status, ruling["final"], truth, ruling["vulnerability_type"], extra))

    print("\nDebate only:          " + score(results, "verdict"))
    if run_validation:
        print("Debate + exploit:     " + score(results, "final"))

    Path("results.json").write_text(json.dumps(results, indent=2))
    print("\nFull transcripts saved to results.json")


if __name__ == "__main__":
    args = sys.argv[1:]
    validate_flag = "--no-validate" not in args
    paths = [a for a in args if not a.startswith("--")]
    main(paths[0] if paths else "../web3-attack-pocs", validate_flag)
