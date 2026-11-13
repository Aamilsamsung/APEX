"""Restore the checked-in, compressed AEGIS PKI source snapshot."""
import base64
import json
import lzma
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
chunks = sorted((ROOT / "source_snapshot").glob("part-*.txt"))
if not chunks:
    raise SystemExit("Source bundle is missing.")
encoded = "".join(p.read_text(encoding="ascii").strip() for p in chunks)
files = json.loads(lzma.decompress(base64.b64decode(encoded)).decode("utf-8"))
for entry in files:
    relative = Path(entry["path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"Unsafe path: {relative}")
    target = (ROOT / relative).resolve()
    if not target.is_relative_to(ROOT):
        raise ValueError(f"Path escapes repository: {relative}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(entry["content"], encoding="utf-8")
    print(f"Restored {relative}")
print(f"Restored {len(files)} source files.")
