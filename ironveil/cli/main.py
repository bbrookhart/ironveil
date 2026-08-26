"""IRONVEIL command-line interface."""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path
from typing import Any

from ironveil.evaluation.scenarios import SCENARIOS, run_broken_seal, run_scenario
from ironveil.evidence.manifest import verify_manifest
from ironveil.graph.lineage import dependency_impact, trace_device
from ironveil.lab import (
    bootstrap_lab,
    load_bundle,
    load_device,
    load_ground_truth,
    load_policy,
    workspace_path,
)
from ironveil.models import Decision
from ironveil.policy.engine import evaluate_release
from ironveil.sbom.verify import verify_sbom
from ironveil.standards.registry import validate_registry
from ironveil.util import sha256_file


def repo_root() -> Path:
    current = Path.cwd().resolve()
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").exists() and (candidate / "standards").exists():
            return candidate
    raise SystemExit("run ironveil inside the repository")


def emit(value: Any) -> None:
    def serialize(item: Any) -> Any:
        if hasattr(item, "model_dump"):
            return item.model_dump(mode="json")
        if dataclasses.is_dataclass(item) and not isinstance(item, type):
            return dataclasses.asdict(item)
        return str(item)

    print(json.dumps(value, indent=2, default=serialize))


def report(repo: Path):  # type: ignore[no-untyped-def]
    bundle = load_bundle(repo)
    device = load_device(repo)
    return evaluate_release(
        bundle,
        device,
        load_policy(repo),
        workspace_path(repo) / "trust" / "LOCAL_TEST_ONLY.pub.pem",
        load_ground_truth(repo),
    )


def _artifact_observed(repo: Path, argument: str) -> str | None:
    path = Path(argument)
    if path.exists():
        return sha256_file(path)
    bundle = load_bundle(repo)
    if argument in {bundle.artifact.name, bundle.artifact.digest, "golden"}:
        return bundle.artifact.digest
    return None


def _verification_check(repo: Path, prefix: str) -> int:
    verification = report(repo)
    checks = [item for item in verification.checks if item.control.startswith(prefix)]
    emit({"decision": verification.decision, "checks": checks})
    return 0 if checks and all(item.state == "VERIFIED" for item in checks) else 1


def command_status(repo: Path) -> int:
    if not workspace_path(repo).exists():
        bootstrap_lab(repo)
    errors = validate_registry(repo / "standards" / "registry.yaml")
    verification = report(repo)
    emit(
        {
            "program": "IRONVEIL",
            "version": "0.1.0",
            "mode": "SYNTHETIC_LOCAL_RESEARCH",
            "lab": "READY",
            "release": verification.release_id,
            "decision": verification.decision,
            "standards_registry": "VERIFIED" if not errors else "FAILED",
            "standards_errors": errors,
            "claims": {
                "hardware_secure_boot": "NOT_CLAIMED",
                "tuf_conformance": "NOT_CLAIMED",
                "uptane_conformance": "NOT_CLAIMED",
                "slsa_level": "NOT_SELF_AWARDED",
            },
        }
    )
    return 0 if verification.decision == Decision.ALLOW and not errors else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ironveil", description="Verify an artifact's history from source to installed state."
    )
    sub = parser.add_subparsers(dest="area", required=True)
    sub.add_parser("status")

    source = sub.add_parser("source")
    source_sub = source.add_subparsers(dest="action", required=True)
    source_verify = source_sub.add_parser("verify")
    source_verify.add_argument("revision")

    build = sub.add_parser("build")
    build_sub = build.add_subparsers(dest="action", required=True)
    build_inspect = build_sub.add_parser("inspect")
    build_inspect.add_argument("artifact")

    provenance = sub.add_parser("provenance")
    provenance_sub = provenance.add_subparsers(dest="action", required=True)
    provenance_verify = provenance_sub.add_parser("verify")
    provenance_verify.add_argument("artifact")

    sbom = sub.add_parser("sbom")
    sbom_sub = sbom.add_subparsers(dest="action", required=True)
    for action in ("inspect", "verify"):
        command = sbom_sub.add_parser(action)
        command.add_argument("artifact")

    signature = sub.add_parser("signature")
    signature_sub = signature.add_subparsers(dest="action", required=True)
    signature_verify = signature_sub.add_parser("verify")
    signature_verify.add_argument("artifact")

    release = sub.add_parser("release")
    release_sub = release.add_subparsers(dest="action", required=True)
    for action in ("inspect", "verify"):
        command = release_sub.add_parser(action)
        command.add_argument("release")

    target = sub.add_parser("target")
    target_sub = target.add_subparsers(dest="action", required=True)
    target_inspect = target_sub.add_parser("inspect")
    target_inspect.add_argument("device")

    update = sub.add_parser("update")
    update_sub = update.add_subparsers(dest="action", required=True)
    for action in ("verify", "apply"):
        command = update_sub.add_parser(action)
        command.add_argument("release")
        command.add_argument("device")

    installed = sub.add_parser("installed")
    installed_sub = installed.add_subparsers(dest="action", required=True)
    installed_verify = installed_sub.add_parser("verify")
    installed_verify.add_argument("device")

    graph = sub.add_parser("graph")
    graph_sub = graph.add_subparsers(dest="action", required=True)
    graph_trace = graph_sub.add_parser("trace")
    graph_trace.add_argument("subject")

    impact = sub.add_parser("impact")
    impact_sub = impact.add_subparsers(dest="action", required=True)
    dependency = impact_sub.add_parser("dependency")
    dependency.add_argument("component")

    recall = sub.add_parser("recall")
    recall_sub = recall.add_subparsers(dest="action", required=True)
    component = recall_sub.add_parser("component")
    component.add_argument("purl")

    scenario = sub.add_parser("scenario")
    scenario_sub = scenario.add_subparsers(dest="action", required=True)
    scenario_sub.add_parser("list")
    scenario_run = scenario_sub.add_parser("run")
    scenario_run.add_argument("scenario_id")

    experiment = sub.add_parser("experiment")
    experiment_sub = experiment.add_subparsers(dest="action", required=True)
    experiment_run = experiment_sub.add_parser("run")
    experiment_run.add_argument("experiment_id")

    evidence = sub.add_parser("evidence")
    evidence_sub = evidence.add_subparsers(dest="action", required=True)
    evidence_verify = evidence_sub.add_parser("verify")
    evidence_verify.add_argument("release")

    lab = sub.add_parser("lab")
    lab_sub = lab.add_subparsers(dest="action", required=True)
    for action in ("init", "up", "health", "down"):
        lab_sub.add_parser(action)
    return parser


def dispatch(args: argparse.Namespace, repo: Path) -> int:  # noqa: C901, PLR0911, PLR0912
    area = args.area
    action = getattr(args, "action", None)
    if area == "status":
        return command_status(repo)
    if area == "lab":
        if action in {"init", "up"}:
            bundle, device = bootstrap_lab(repo)
            emit({"status": "READY", "release": bundle.release_id, "device": device.device_id})
            return 0
        if action == "health":
            return command_status(repo)
        lab_file = workspace_path(repo) / "lab.json"
        if lab_file.exists():
            lab_file.write_text('{"status":"STOPPED","mode":"SYNTHETIC_LOCAL_RESEARCH"}\n')
        emit({"status": "STOPPED"})
        return 0
    if not workspace_path(repo).exists():
        bootstrap_lab(repo)
    bundle = load_bundle(repo)
    device = load_device(repo)
    if area == "source":
        valid = args.revision in {bundle.source.revision, "golden"}
        emit({"revision": args.revision, "expected": bundle.source.revision, "verified": valid})
        return 0 if valid else 1
    if area == "build":
        observed = _artifact_observed(repo, args.artifact)
        emit({"artifact": bundle.artifact, "observed_digest": observed})
        return 0 if observed == bundle.artifact.digest else 1
    if area == "provenance":
        return _verification_check(repo, "INV-001.provenance")
    if area == "sbom":
        if action == "inspect":
            emit(bundle.sbom)
            return 0
        if bundle.sbom is None:
            emit({"verified": False, "reason": "SBOM missing"})
            return 1
        valid, detail, metrics = verify_sbom(
            bundle.sbom, bundle.artifact.digest, load_ground_truth(repo)
        )
        emit({"verified": valid, "detail": detail, "metrics": metrics.__dict__})
        return 0 if valid else 1
    if area == "signature":
        return _verification_check(repo, "INV-002.signature")
    if area == "release":
        if action == "inspect":
            emit(bundle)
            return 0
        verification = report(repo)
        emit(verification)
        return 0 if verification.decision == Decision.ALLOW else 1
    if area == "target":
        emit(device)
        return 0
    if area == "update":
        verification = report(repo)
        if action == "apply" and verification.decision == Decision.ALLOW:
            device.last_known_good_digest = device.artifact_digest
            device.installed_version = bundle.artifact.version
            device.artifact_digest = bundle.artifact.digest
            device.sbom_digest = (
                bundle.evidence_manifest.evidence_digests["sbom"]
                if bundle.evidence_manifest
                else "UNKNOWN"
            )
            (workspace_path(repo) / "devices" / f"{device.device_id}.json").write_text(
                device.model_dump_json(indent=2) + "\n"
            )
        emit({"decision": verification.decision, "action": action})
        return 0 if verification.decision == Decision.ALLOW else 1
    if area == "installed":
        matched = device.artifact_digest == bundle.artifact.digest
        emit(
            {
                "device": device.device_id,
                "intended_digest": bundle.artifact.digest,
                "installed_digest": device.artifact_digest,
                "state": "VERIFIED" if matched else "DEPLOYMENT_DRIFT",
            }
        )
        return 0 if matched else 2
    if area == "graph":
        emit({"subject": args.subject, "trace": trace_device(bundle, device)})
        return 0
    if area in {"impact", "recall"}:
        purl = args.component if area == "impact" else args.purl
        emit(dependency_impact(bundle, device, purl))
        return 0
    if area == "scenario":
        if action == "list":
            emit([item.model_dump(mode="json") for item in SCENARIOS])
            return 0
        run = run_scenario(repo, args.scenario_id)
        emit(
            {
                "scenario": run.definition,
                "decision": run.full_decision,
                "signature_only_accepts": run.signature_only_accepts,
                "installation": run.installation,
                "passed": run.passed,
                "checks": run.checks,
            }
        )
        return 0 if run.passed else 1
    if area == "experiment":
        if args.experiment_id.upper() not in {"BROKEN-SEAL", "BROKEN_SEAL"}:
            raise SystemExit("unknown experiment; supported: BROKEN-SEAL")
        result = run_broken_seal(repo)
        emit(result)
        return 0 if result["scenario_pass_rate"] == 1.0 else 1
    if area == "evidence":
        valid, detail = verify_manifest(bundle)
        emit({"release": args.release, "verified": valid, "detail": detail})
        return 0 if valid else 1
    raise SystemExit(f"unhandled command: {area} {action}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        code = dispatch(args, repo_root())
    except (KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        code = 2
    raise SystemExit(code)


if __name__ == "__main__":
    main()
