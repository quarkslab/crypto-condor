"""Script to add a new primitive."""

import sys
from pathlib import Path

ROOT = Path("crypto_condor")


def usage(code: int = 0):
    """Prints usage and exits with exit code."""
    print("Usage: python utils/add_primitive.py <primitive>")
    exit(code)


def _create_primitive(primitive: str):
    print("[...] Copy primitive template", end="\r")
    template = (
        Path("utils/templates/new-primitive.py")
        .read_text()
        .replace("CapPLACEHOLDER", primitive.capitalize())
        .replace("LCPLACEHOLDER", primitive.lower())
        .replace("PLACEHOLDER", primitive)
    )
    Path(ROOT / f"primitives/{primitive}.py").write_text(template)
    print("[OK ] Copy primitive template")


def _create_vectors(primitive: str):
    primitive = primitive.lower()

    print("[...] Create vectors directory", end="\r")
    Path(ROOT / "vectors" / f"_{primitive}").mkdir(0o755, parents=False, exist_ok=True)
    print("[OK ] Create vectors directory")

    print("[...] Create .proto file", end="\r")
    template = (
        Path("utils/templates/new-vectors.proto")
        .read_text()
        .replace("CapPLACEHOLDER", primitive.capitalize())
        .replace("PLACEHOLDER", primitive)
    )
    Path(ROOT / f"vectors/_{primitive}/{primitive}.proto").write_text(template)
    print("[OK ] Create .proto file")

    print("[...] Create vectors import file", end="\r")
    template = (
        Path("utils/templates/new-vectors-import.py")
        .read_text()
        .replace("CapPLACEHOLDER", primitive.capitalize())
        .replace("LCPLACEHOLDER", primitive.lower())
        .replace("PLACEHOLDER", primitive)
    )
    Path(ROOT / f"vectors/_{primitive}/{primitive}_import.py").write_text(template)
    print("[OK ] Create vectors import file")

    print("[...] Create vectors file", end="\r")
    template = (
        Path("utils/templates/new-vectors.py")
        .read_text()
        .replace("PLACEHOLDER", primitive)
    )
    Path(ROOT / f"vectors/{primitive}.py").write_text(template)
    print("[OK ] Create vectors file")


def _create_wrappers(primitive: str):
    print("[...] Create wrappers directory", end="\r")
    Path(ROOT / f"resources/wrappers/{primitive}").mkdir(
        0o755, parents=False, exist_ok=True
    )
    print("[OK ] Create wrappers directory")


def _create_docs(primitive: str):
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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage(1)

    if sys.argv[0] != "utils/add_primitive.py":
        print("Paths are relative to the root of the repo.")
        usage(1)

    primitive = sys.argv[1]
    print(f"[+] Creating files and directories for {primitive}")

    _create_primitive(primitive)
    _create_vectors(primitive)
    _create_wrappers(primitive)
    _create_docs(primitive)

    print(f"Don't forget to add {primitive} to constants.py!")
