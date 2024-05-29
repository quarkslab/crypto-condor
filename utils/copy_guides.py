"""Script to copy the guides to the tool."""

import shutil
from pathlib import Path

DOCS_DIR = Path("docs/source/method")
GUIDES_DIR = Path("crypto_condor/resources/guides")

assert DOCS_DIR.is_dir()
assert GUIDES_DIR.is_dir()

for item in DOCS_DIR.iterdir():
    if (
        not item.is_file()
        or item.suffix == ".bib"
        or item.name == "index.md"
        or item.name == "post-quantum.md"
    ):
        continue
    dst = GUIDES_DIR / item.name
    print(f"[+] Copy {item.stem} guide...", end=" ", flush=True)
    shutil.copyfile(item, dst)
    print("OK")
