"""A stand-in custom tool: renders N deterministic assets and compresses each, so a rebuild costs CPU and its output is a large tree of opaque blobs."""
import hashlib
import os
import sys
import zlib

out, count, raw = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
os.makedirs(out, exist_ok=True)
for i in range(count):
    stream = hashlib.shake_256(b"b05-%d" % i).digest(raw // 4)
    data = (stream.hex().encode() + b"\n") * 2
    with open(os.path.join(out, "asset-%05d.z" % i), "wb") as f:
        f.write(zlib.compress(data[:raw], 1))
