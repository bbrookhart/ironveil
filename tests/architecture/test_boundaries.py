from pathlib import Path

import yaml


def test_compose_does_not_expose_docker_socket_or_broad_network(repo_root: Path) -> None:
    compose = (repo_root / "docker-compose.yml").read_text()
    assert "/var/run/docker.sock" not in compose
    assert "0.0.0.0:" not in compose
    assert "cap_drop" in compose
    assert "no-new-privileges" in compose


def test_workflows_use_least_privilege(repo_root: Path) -> None:
    for path in (repo_root / ".github" / "workflows").glob("*.yml"):
        text = path.read_text()
        assert "write-all" not in text
        assert "permissions:" in text


def test_policy_does_not_use_wildcard_identity(repo_root: Path) -> None:
    policy = yaml.safe_load((repo_root / "policies" / "release-policy.yaml").read_text())
    for field in (
        "expected_repository",
        "expected_builder",
        "expected_workflow",
        "expected_signer",
    ):
        assert policy[field] not in {".*", "*"}
