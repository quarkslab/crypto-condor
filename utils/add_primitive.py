"""Script to add a new primitive."""

import sys
from pathlib import Path


def usage(code: int = 0):
    """Prints usage and exits with exit code."""
    print("Usage: python utils/add_primitive.py <primitive>")
    exit(code)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage(1)

    if sys.argv[0] != "utils/add_primitive.py":
        print("Paths are relative to the root of the repo.")
        usage(1)

    primitive = sys.argv[1]

    print(f"[+] Creating files and directories for {primitive}")

    root = Path("crypto_condor")

    # Primitive
    print("[...] Copy primitive template", end="\r")
    template = (
        Path("utils/templates/new-primitive.py")
        .read_text()
        .replace("PLACEHOLDER", primitive)
    )
    Path(root / f"primitives/{primitive}.py").write_text(template)
    print("[OK ] Copy primitive template")

    # Vectors
    print("[...] Create vectors directory", end="\r")
    Path(root / "vectors" / f"_{primitive}").mkdir(0o755, parents=False, exist_ok=True)
    print("[OK ] Create vectors directory")

    print("[...] Create .proto file", end="\r")
    template = (
        Path("utils/templates/new-vectors.proto")
        .read_text()
        .replace("PLACEHOLDER", primitive)
    )
    Path(root / f"vectors/{primitive}.proto").write_text(template)
    print("[OK ] Create .proto file")

    print("[...] Create .json file", end="\r")
    Path(root / f"vectors/{primitive}.json").touch()
    print("[OK ] Create .json file")

    # Wrappers
    print("[...] Create wrappers directory", end="\r")
    Path(root / f"resources/wrappers/{primitive}").mkdir(
        0o755, parents=False, exist_ok=True
    )
    print("[OK ] Create wrappers directory")

    # Docs
    print("[...] Copy docs templates", end="\r")
    template = (
        Path("utils/templates/new-docs-method.md")
        .read_text()
        .replace("PLACEHOLDER", primitive)
    )
    Path(f"docs/source/method/{primitive}.md").write_text(template)
    template = (
        Path("utils/templates/new-docs-module.rst")
        .read_text()
        .replace("PLACEHOLDER", primitive)
    )
    Path(f"docs/source/python-api/primitives/{primitive}.rst").write_text(template)
    print("[OK ] Copy docs templates")

    print(f"Don't forget to add {primitive} to constants.py!")
