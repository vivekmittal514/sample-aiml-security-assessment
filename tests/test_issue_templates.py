from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
ISSUE_TEMPLATE_DIR = REPO_ROOT / ".github" / "ISSUE_TEMPLATE"


def test_blank_issues_are_disabled():
    config = yaml.safe_load(
        (ISSUE_TEMPLATE_DIR / "config.yml").read_text(encoding="utf-8")
    )

    assert config["blank_issues_enabled"] is False
