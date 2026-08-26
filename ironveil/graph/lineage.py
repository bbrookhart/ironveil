"""Provenance lineage and dependency blast-radius graph."""

from __future__ import annotations

from typing import Any

import networkx as nx

from ironveil.models import DeviceState, ReleaseBundle


def build_graph(bundle: ReleaseBundle, device: DeviceState) -> nx.DiGraph[str]:
    graph: nx.DiGraph[str] = nx.DiGraph()
    revision = f"COMMIT-{bundle.source.revision[:12]}"
    build = "BUILD-00001"
    artifact = bundle.artifact.digest
    release = bundle.release_id
    graph.add_node(revision, kind="Commit")
    graph.add_node("REVIEW-001", kind="Review")
    graph.add_node(build, kind="Build")
    graph.add_node(artifact, kind="Artifact", version=bundle.artifact.version)
    graph.add_node(release, kind="Release")
    graph.add_node(device.device_id, kind="Device")
    graph.add_node("MISSION-TELEMETRY", kind="MissionFunction")
    graph.add_edge("REVIEW-001", revision, relation="REVIEWED")
    graph.add_edge(revision, build, relation="BUILT_FROM")
    graph.add_edge(build, artifact, relation="PRODUCED")
    graph.add_edge(artifact, release, relation="AUTHORIZED_AS")
    graph.add_edge(release, device.device_id, relation="TARGETS")
    graph.add_edge(device.device_id, "MISSION-TELEMETRY", relation="SUPPORTS")
    if bundle.sbom:
        for component in bundle.sbom.components:
            graph.add_node(component.purl, kind="Dependency")
            graph.add_edge(component.purl, artifact, relation="DEPENDS_ON")
    return graph


def trace_device(bundle: ReleaseBundle, device: DeviceState) -> list[dict[str, str]]:
    graph = build_graph(bundle, device)
    revision = f"COMMIT-{bundle.source.revision[:12]}"
    path = nx.shortest_path(graph, revision, device.device_id)
    rows: list[dict[str, str]] = []
    for source, target in zip(path, path[1:], strict=False):
        rows.append(
            {
                "source": source,
                "relation": graph.edges[source, target]["relation"],
                "target": target,
            }
        )
    return rows


def dependency_impact(
    bundle: ReleaseBundle, device: DeviceState, component_purl: str
) -> dict[str, Any]:
    graph = build_graph(bundle, device)
    if component_purl not in graph:
        return {
            "component": component_purl,
            "affected_releases": [],
            "affected_artifacts": [],
            "affected_devices": [],
            "affected_mission_functions": [],
            "recommended_response_scope": (
                "No synthetic inventory match; verify identifier and refresh inventory."
            ),
        }
    descendants = nx.descendants(graph, component_purl)

    def by_kind(kind: str) -> list[str]:
        return sorted(node for node in descendants if graph.nodes[node].get("kind") == kind)

    return {
        "component": component_purl,
        "affected_releases": by_kind("Release"),
        "affected_artifacts": by_kind("Artifact"),
        "affected_devices": by_kind("Device"),
        "affected_mission_functions": by_kind("MissionFunction"),
        "recommended_response_scope": (
            "Quarantine affected device group, validate replacement evidence, and issue a "
            "target-bound recall."
        ),
    }
