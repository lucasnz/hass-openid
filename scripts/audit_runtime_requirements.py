#!/usr/bin/env python3
"""Audit Python dependencies owned by the custom integration.

Home Assistant and pytest-homeassistant-custom-component select the versions of
Home Assistant's own runtime and test dependencies. Auditing
requirements_test.txt therefore reports vulnerabilities in that upstream test
environment which this custom integration cannot safely override.

This script instead audits the integration-owned requirements declared in
manifest.json. The separate informational workflow step still reports
vulnerabilities in the complete Home Assistant test stack.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = (
    REPOSITORY_ROOT / "custom_components" / "openid" / "manifest.json"
)


def main() -> None:
    """Audit the dependency tree rooted at manifest requirements."""
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    requirements = manifest.get("requirements", [])

    if not isinstance(requirements, list) or not all(
        isinstance(requirement, str) and requirement.strip()
        for requirement in requirements
    ):
        raise SystemExit("manifest.json requirements must be a list of strings")

    if not requirements:
        print("No integration-owned Python runtime requirements to audit.")
        return

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".txt",
    ) as requirements_file:
        requirements_file.write("\n".join(requirements))
        requirements_file.write("\n")
        requirements_file.flush()
        subprocess.run(
            [
                "pip-audit",
                "--progress-spinner",
                "off",
                "-r",
                requirements_file.name,
            ],
            check=True,
        )


if __name__ == "__main__":
    main()
