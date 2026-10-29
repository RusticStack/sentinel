#!/usr/bin/env python3
"""Stand-in for the Git fixture server of the B09 kit: the fake controller reads the pipeline from the bare
repository directly, so this only has to stay alive and show its arguments once."""
import sys
import time

print("fake b09-git up:", *sys.argv[1:2], flush=True)
while True:
    time.sleep(3600)
