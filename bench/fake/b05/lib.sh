# Shared by the stub toolchains of the B05 smoke profile. They create the directories a real toolchain would leave
# (so file counts and sizes exist), log every call to FAKE_LOG, and fail where the real one would: offline or
# GOPROXY=off with an empty cache. FAKE_FAIL=<tool> makes that tool exit 1. They measure nothing.
fake_log() { [ -n "${FAKE_LOG:-}" ] && printf '%s %s\n' "$FAKE_TOOL" "$*" >> "$FAKE_LOG"; return 0; }
fake_fail_if_asked() { if [ "${FAKE_FAIL:-}" = "$FAKE_TOOL" ]; then echo "$FAKE_TOOL: failing on request (FAKE_FAIL)" >&2; exit 1; fi; }
populate() { # dir count
  mkdir -p "$1" || exit 1
  local i
  for i in $(seq 1 "${2:-3}"); do printf 'fake %s\n' "$i" > "$1/f$i"; done
}
has_files() { [ -d "$1" ] && [ -n "$(find "$1" -type f -print -quit 2>/dev/null)" ]; }
fake_start() { # tool args...
  FAKE_TOOL="$1"; shift
  fake_log "$@"
  fake_fail_if_asked
}
