"""Script for pre-push hook.

Checks if the last commit has a tag. If it does, it checks that the tag corresponds
to the tool's version (modulo some normalization).
"""

import subprocess
from importlib import metadata

from packaging import version


def main():  # noqa: D103
    # Get current commit's tag, if any.
    result = subprocess.run(
        ["git", "tag", "--points-at", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )

    if not result.stdout:
        print("No tag found for current commit.")
        exit(0)

    tag = version.parse(result.stdout)
    ver = version.parse(metadata.version("crypto-condor"))

    if tag != ver:
        print(f"Tag version: {tag}")
        print(f"Package version: {ver}")
        exit(1)

    exit(0)


if __name__ == "__main__":
    main()
