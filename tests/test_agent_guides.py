from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_agent_guide_documents_repository_ruff_configuration():
    guide = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")

    assert "Ruff automatically loads the repository's ruff.toml" in guide
    assert "no config file, defaults" not in guide


def test_claude_guide_imports_canonical_agent_guide_without_duplication():
    guide = (REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8")

    assert "@AGENTS.md" in guide.splitlines()
    assert "## Commands" not in guide
    assert len(guide.splitlines()) <= 8
