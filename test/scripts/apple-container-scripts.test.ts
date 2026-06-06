// Apple Container script tests exercise the shared bash helpers under
// scripts/apple-container/lib/ (JSON parsers, Keychain reads, preflight)
// plus the staged -h/--help behavior of openclaw-tui.sh.
//
// The helpers are source-only bash libraries, so each test spawns a clean
// bash child (--noprofile --norc) and either:
//   * sets PATH to a temp dir with stub `container` / `tailscale` binaries
//     to drive the JSON parsers against controlled fixtures, or
//   * uses the real /usr/bin/security CLI with a unique throwaway service
//     name to verify the Keychain dedup without touching user state.
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const REPO_ROOT = process.cwd();
const CONTAINER_JSON_LIB = `${REPO_ROOT}/scripts/apple-container/lib/container-json.sh`;
const PREFLIGHT_LIB = `${REPO_ROOT}/scripts/apple-container/lib/preflight.sh`;
const TUI_SCRIPT = `${REPO_ROOT}/scripts/apple-container/openclaw-tui.sh`;

interface BashRunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runBash(body: string, env: Record<string, string> = {}): BashRunResult {
  const result = spawnSync("bash", ["--noprofile", "--norc", "-c", body], {
    encoding: "utf8",
    env: {
      ...process.env,
      NO_COLOR: "1",
      ...env,
    },
  });
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

function makeMockBinDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "openclaw-ac-mock-"));
  return dir;
}

function writeStub(dir: string, name: string, script: string): void {
  writeFileSync(join(dir, name), script, { mode: 0o755 });
}

let mockBinDir: string;
beforeEach(() => {
  mockBinDir = makeMockBinDir();
});

afterEach(() => {
  if (mockBinDir) {
    rmSync(mockBinDir, { recursive: true, force: true });
  }
});

describe("lib/container-json.sh — JSON parsers", () => {
  it("extracts .status from container system status JSON", () => {
    writeStub(
      mockBinDir,
      "container",
      `#!/usr/bin/env bash
if [[ "$1 $2 $3 $4" == "system status --format json" ]]; then
  printf '%s' '{"status":"running","extra":"ignored"}'
fi
`,
    );
    const { status, stdout, stderr } = runBash(
      `source ${CONTAINER_JSON_LIB}\nprintf '%s' "$(parse_container_system_status)"\n`,
      { PATH: `${mockBinDir}:${process.env.PATH ?? ""}` },
    );
    expect(stderr).toBe("");
    expect(status).toBe(0);
    expect(stdout).toBe("running");
  });

  it("extracts .BackendState from tailscale status --json", () => {
    writeStub(
      mockBinDir,
      "tailscale",
      `#!/usr/bin/env bash
if [[ "$1 $2" == "status --json" ]]; then
  printf '%s' '{"BackendState":"Running","Peer":{}}'
fi
`,
    );
    const { status, stdout, stderr } = runBash(
      `source ${CONTAINER_JSON_LIB}\nprintf '%s' "$(parse_tailscale_backend_state)"\n`,
      { PATH: `${mockBinDir}:${process.env.PATH ?? ""}` },
    );
    expect(stderr).toBe("");
    expect(status).toBe(0);
    expect(stdout).toBe("Running");
  });

  it("extracts the first https?:// origin from tailscale serve status", () => {
    writeStub(
      mockBinDir,
      "tailscale",
      `#!/usr/bin/env bash
if [[ "$1 $2" == "serve status" ]]; then
  printf 'https://my-machine.ts.net\\nhttps://other.ts.net\\n'
fi
`,
    );
    const { status, stdout, stderr } = runBash(
      `source ${CONTAINER_JSON_LIB}\nprintf '%s' "$(parse_tailscale_origin)"\n`,
      { PATH: `${mockBinDir}:${process.env.PATH ?? ""}` },
    );
    expect(stderr).toBe("");
    expect(status).toBe(0);
    expect(stdout).toBe("https://my-machine.ts.net");
  });

  it("extracts the container gateway CIDR from container inspect", () => {
    writeStub(
      mockBinDir,
      "container",
      `#!/usr/bin/env bash
if [[ "$1" == "inspect" ]]; then
  printf '%s' '[{"networks":[{"ipv4Address":"192.168.64.5/24"}]}]'
fi
`,
    );
    const { status, stdout, stderr } = runBash(
      `source ${CONTAINER_JSON_LIB}\nprintf '%s' "$(parse_container_gateway_cidr openclaw)"\n`,
      { PATH: `${mockBinDir}:${process.env.PATH ?? ""}` },
    );
    expect(stderr).toBe("");
    expect(status).toBe(0);
    expect(stdout).toBe("192.168.64.0/24");
  });

  it("extracts the network IPv4 gateway from container network inspect", () => {
    writeStub(
      mockBinDir,
      "container",
      `#!/usr/bin/env bash
if [[ "$1 $2" == "network inspect" ]]; then
  printf '%s' '[{"status":{"ipv4Gateway":"192.168.64.1"}}]'
fi
`,
    );
    const { status, stdout, stderr } = runBash(
      `source ${CONTAINER_JSON_LIB}\nprintf '%s' "$(parse_container_network_gateway openclaw-net)"\n`,
      { PATH: `${mockBinDir}:${process.env.PATH ?? ""}` },
    );
    expect(stderr).toBe("");
    expect(status).toBe(0);
    expect(stdout).toBe("192.168.64.1");
  });

  it("emits a one-shot stderr WARN when a schema change drops the payload", () => {
    // Schema changed: status moved under .runtime.state — parser returns empty.
    writeStub(
      mockBinDir,
      "container",
      `#!/usr/bin/env bash
if [[ "$1 $2 $3 $4" == "system status --format json" ]]; then
  printf '%s' '{"runtime":{"state":"running"}}'
fi
`,
    );
    const { status, stdout, stderr } = runBash(
      `source ${CONTAINER_JSON_LIB}
result="$(parse_container_system_status)"
printf 'OUT=%s\\n' "$result"
`,
      { PATH: `${mockBinDir}:${process.env.PATH ?? ""}` },
    );
    expect(status).toBe(0);
    expect(stdout).toBe("OUT=\n");
    expect(stderr).toContain("WARN: parse_container_system_status could not parse CLI output.");
    expect(stderr).toContain("scripts/apple-container/lib/container-json.sh");
  });

  it("does not warn twice for the same dropped label", () => {
    writeStub(
      mockBinDir,
      "container",
      `#!/usr/bin/env bash
if [[ "$1 $2 $3 $4" == "system status --format json" ]]; then
  printf '%s' '{"runtime":{"state":"running"}}'
fi
`,
    );
    const { status, stderr } = runBash(
      `source ${CONTAINER_JSON_LIB}
parse_container_system_status >/dev/null
parse_container_system_status >/dev/null
`,
      { PATH: `${mockBinDir}:${process.env.PATH ?? ""}` },
    );
    expect(status).toBe(0);
    const matches = stderr.match(/WARN: parse_container_system_status/g) ?? [];
    expect(matches).toHaveLength(1);
  });

  it("does not warn when the CLI itself is missing (empty raw)", () => {
    // Simulate "container not installed" by shadowing it with a stub that
    // always fails. The parser should treat the resulting empty `raw` as
    // normal and stay silent.
    writeStub(
      mockBinDir,
      "container",
      `#!/usr/bin/env bash
exit 127
`,
    );
    const { status, stdout, stderr } = runBash(
      `source ${CONTAINER_JSON_LIB}\nprintf '%s' "X$(parse_container_system_status)Y"\n`,
      { PATH: `${mockBinDir}:${process.env.PATH ?? ""}` },
    );
    expect(status).toBe(0);
    expect(stdout).toBe("XY");
    expect(stderr).toBe("");
  });

  it("returns empty for parse_container_gateway_cidr when name is unset", () => {
    const { status, stdout, stderr } = runBash(
      `source ${CONTAINER_JSON_LIB}\nprintf '%s' "X$(parse_container_gateway_cidr)Y"\n`,
      { PATH: `${mockBinDir}:${process.env.PATH ?? ""}` },
    );
    expect(status).toBe(0);
    expect(stdout).toBe("XY");
    expect(stderr).toBe("");
  });
});

describe("lib/container-json.sh — Keychain dedup (read-only)", () => {
  // We deliberately avoid security add-generic-password here: writing to the
  // user login keychain from a test runner is risky, and a crashed run could
  // leave a stale item behind. The helpers are exercised against a service
  // name we never write, so both functions return their "missing" defaults.

  it("read_keychain_token prints nothing and keychain_token_exists returns 1 for a missing service", () => {
    const probeService = "ai.openclaw.test.apple-container-scripts.never-written";
    const { status, stdout, stderr } = runBash(
      `source ${CONTAINER_JSON_LIB}
token="$(read_keychain_token '${probeService}' test-account)"
exists=0
keychain_token_exists '${probeService}' test-account || exists=1
printf 'TOKEN=%s EXISTS=%d\\n' "$token" "$exists"
`,
    );
    expect(status).toBe(0);
    expect(stderr).toBe("");
    expect(stdout.trimEnd()).toBe("TOKEN= EXISTS=1");
  });

  it("read_keychain_token prints nothing and keychain_token_exists returns 1 for an empty service", () => {
    const { status, stdout, stderr } = runBash(
      `source ${CONTAINER_JSON_LIB}
token="$(read_keychain_token '' test-account)"
exists=0
keychain_token_exists '' test-account || exists=1
printf 'TOKEN=%s EXISTS=%d\\n' "$token" "$exists"
`,
    );
    expect(status).toBe(0);
    expect(stderr).toBe("");
    expect(stdout.trimEnd()).toBe("TOKEN= EXISTS=1");
  });
});

describe("lib/preflight.sh — output primitives", () => {
  it("emits the title and counts in preflight_summary", () => {
    const { stdout, stderr } = runBash(
      `source ${PREFLIGHT_LIB}
preflight_init "unit test"
preflight_pass "alpha"
preflight_fail "beta" "hint"
preflight_skip "gamma" "why"
preflight_summary || true
`,
    );
    expect(stderr).toBe("");
    expect(stdout).toContain("unit test");
    expect(stdout).toContain("✓ alpha");
    expect(stdout).toContain("✗ beta");
    expect(stdout).toContain("• gamma");
    expect(stdout).toContain("1 failed, 1 skipped, 1 passed");
  });

  it("preflight_summary returns non-zero when any check failed", () => {
    const { status, stdout } = runBash(
      `source ${PREFLIGHT_LIB}
preflight_init "fail mode"
preflight_pass "ok"
preflight_fail "bad" "reason"
preflight_summary
`,
    );
    expect(status).not.toBe(0);
    expect(stdout).toMatch(/1 failed, 0 skipped, 1 passed/);
  });

  it("preflight_summary returns 0 with skips-only output", () => {
    const { status, stdout } = runBash(
      `source ${PREFLIGHT_LIB}
preflight_init "warn mode"
preflight_pass "ok"
preflight_skip "maybe" "later"
preflight_summary
`,
    );
    expect(status).toBe(0);
    expect(stdout).toMatch(/1 skipped, 1 passed \(warnings only\)/);
  });

  it("respects NO_COLOR by stripping ANSI escapes", () => {
    const { stdout } = runBash(
      `source ${PREFLIGHT_LIB}
preflight_init "no color"
preflight_pass "x"
`,
      { NO_COLOR: "1" },
    );
    expect(stdout.includes("\u001b[")).toBe(false);
  });
});

describe("lib/preflight.sh — real environment checks", () => {
  it("preflight_check_macos passes on darwin", () => {
    const { status, stdout } = runBash(
      `source ${PREFLIGHT_LIB}
preflight_init "macos"
preflight_check_macos
preflight_summary
`,
    );
    expect(status).toBe(0);
    expect(stdout).toContain("✓ macOS");
  });

  it("preflight_check_security passes because /usr/bin/security is on the host", () => {
    const { status, stdout } = runBash(
      `source ${PREFLIGHT_LIB}
preflight_init "sec"
preflight_check_security
preflight_summary
`,
    );
    expect(status).toBe(0);
    expect(stdout).toContain("✓ macOS Keychain CLI");
  });

  it("preflight_check_curl and preflight_check_node pass on the test host", () => {
    const { status, stdout } = runBash(
      `source ${PREFLIGHT_LIB}
preflight_init "deps"
preflight_check_curl
preflight_check_node
preflight_summary
`,
    );
    expect(status).toBe(0);
    expect(stdout).toContain("✓ curl");
    expect(stdout).toMatch(/✓ node ≥ 22/);
  });
});

describe("lib/preflight.sh — mocked missing-binary checks", () => {
  it("preflight_check_apple_container_cli fails with the install hint when container is absent", () => {
    const { status, stdout } = runBash(
      `source ${PREFLIGHT_LIB}
preflight_init "no cli"
preflight_check_apple_container_cli
preflight_summary
`,
      { PATH: "/usr/bin:/bin" },
    );
    expect(status).not.toBe(0);
    expect(stdout).toContain("✗ Apple Container CLI");
    expect(stdout).toContain("https://github.com/apple/container/releases");
  });

  it("preflight_check_tailscale is skippable via OPENCLAW_SKIP_TAILSCALE_CHECK=1", () => {
    const { status, stdout } = runBash(
      `source ${PREFLIGHT_LIB}
preflight_init "skip ts"
preflight_check_tailscale
preflight_summary
`,
      { OPENCLAW_SKIP_TAILSCALE_CHECK: "1" },
    );
    expect(status).toBe(0);
    expect(stdout).toContain("• tailscale");
    expect(stdout).toContain("OPENCLAW_SKIP_TAILSCALE_CHECK is set");
  });
});

describe("lib/preflight.sh — safe_mktemp_dir", () => {
  it("creates a directory under TMPDIR", () => {
    const { status, stdout, stderr } = runBash(
      `fail() { echo "FAIL: $*" >&2; exit 1; }
source ${PREFLIGHT_LIB}
d="$(safe_mktemp_dir openclaw-test.XXXXXX)"
[[ -d "$d" ]] || { echo "not a dir: $d" >&2; exit 2; }
rmdir "$d"
printf 'OK\\n'
`,
      { TMPDIR: tmpdir() },
    );
    expect(stderr).toBe("");
    expect(status).toBe(0);
    expect(stdout).toBe("OK\n");
  });

  it("calls fail when the template is missing XXXXXX", () => {
    const { stderr } = runBash(
      `fail() { echo "FAIL: $*" >&2; exit 1; }
source ${PREFLIGHT_LIB}
safe_mktemp_dir "no-template" || true
`,
    );
    expect(stderr).toContain("FAIL: safe_mktemp_dir: template must contain XXXXXX");
  });
});

describe("openclaw-tui.sh — usage surface", () => {
  it("prints usage and exits 0 on -h", () => {
    const { status, stdout, stderr } = runBash(`"${TUI_SCRIPT}" -h`);
    expect(status).toBe(0);
    expect(stderr).toBe("");
    expect(stdout).toContain("Usage: openclaw-tui.sh [tui-args...]");
    expect(stdout).toContain("OPENCLAW_APPLE_CONTAINER_TUI_RUNTIME");
    expect(stdout).toContain("scripts/apple-container/run.sh");
  });

  it("prints usage and exits 0 on --help", () => {
    const { status, stdout, stderr } = runBash(`"${TUI_SCRIPT}" --help`);
    expect(status).toBe(0);
    expect(stderr).toBe("");
    expect(stdout).toContain("Usage: openclaw-tui.sh");
  });
});
