"""A build step with content-keyed outputs — the same invalidation a
real bundler/compiler cache performs: one dist file per source, named by
content hash, unchanged inputs never rewritten."""

import hashlib
import pathlib

dist = pathlib.Path("dist")
dist.mkdir(exist_ok=True)
for src in sorted(pathlib.Path("src").glob("*.py")):
    digest = hashlib.sha256(src.read_bytes()).hexdigest()[:16]
    out = dist / f"{src.stem}.{digest}.py"
    if out.exists():
        print(f"reused {src.name}")
        continue
    out.write_bytes(f"# {src.name}\n".encode() + src.read_bytes())
    print(f"built {src.name}")
