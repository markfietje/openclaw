// Exercises MCP stdio process lifecycle, JSON-RPC IO, and close escalation.
import type { SpawnOptions } from "node:child_process";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import { OpenClawStdioClientTransport } from "./mcp-stdio-transport.js";

const spawnMock = vi.hoisted(() => vi.fn());
const killProcessTreeMock = vi.hoisted(() => vi.fn());
const signalProcessTreeMock = vi.hoisted(() => vi.fn());

vi.mock("node:child_process", async () => ({
  ...(await vi.importActual<typeof import("node:child_process")>("node:child_process")),
  spawn: spawnMock,
}));

vi.mock("../process/kill-tree.js", () => ({
  killProcessTree: killProcessTreeMock,
  signalProcessTree: signalProcessTreeMock,
}));

class MockChildProcess extends EventEmitter {
  // Minimal child-process surface needed by the transport: stdio streams,
  // pid, and lifecycle events.
  exitCode: number | null = null;
  pid = 4321;
  stdin = new PassThrough();
  stdout = new PassThrough();
  stderr = new PassThrough();
}

describe("OpenClawStdioClientTransport", () => {
  afterEach(() => {
    vi.useRealTimers();
    spawnMock.mockReset();
    killProcessTreeMock.mockReset();
    signalProcessTreeMock.mockReset();
  });

  it("starts stdio MCP servers in a disposable process group on POSIX", async () => {
    // Detached POSIX process groups let OpenClaw clean up child tool servers
    // without relying on shell-specific process trees.
    const child = new MockChildProcess();
    spawnMock.mockReturnValue(child);

    const transport = new OpenClawStdioClientTransport({
      command: "npx",
      args: ["-y", "example-mcp"],
      env: { EXAMPLE: "1" },
      cwd: "/tmp/example",
      stderr: "pipe",
    });
    const started = transport.start();
    child.emit("spawn");
    await started;

    const [command, args, options] = spawnMock.mock.calls.at(0) as [string, string[], SpawnOptions];
    if (process.platform === "linux") {
      expect(command).toBe("/bin/sh");
      expect(args).toEqual([
        "-c",
        'echo 1000 > /proc/self/oom_score_adj 2>/dev/null; exec "$0" "$@"',
        "npx",
        "-y",
        "example-mcp",
      ]);
    } else {
      expect(command).toBe("npx");
      expect(args).toEqual(["-y", "example-mcp"]);
    }
    expect(options.cwd).toBe("/tmp/example");
    expect(options.detached).toBe(process.platform !== "win32");
    expect(options.shell).toBe(false);
    expect(options.stdio).toEqual(["pipe", "pipe", "pipe"]);
    expect(options.env?.EXAMPLE).toBe("1");
    expect(transport.pid).toBe(4321);
    expect(transport.stderr).toBeInstanceOf(PassThrough);
  });

  it("kills the process tree when graceful stdio close does not exit", async () => {
    vi.useFakeTimers();
    const child = new MockChildProcess();
    spawnMock.mockReturnValue(child);

    const transport = new OpenClawStdioClientTransport({ command: "npx" });
    const started = transport.start();
    child.emit("spawn");
    await started;

    const closing = transport.close();
    await vi.advanceTimersByTimeAsync(2000);
    expect(killProcessTreeMock).toHaveBeenCalledWith(4321);

    child.exitCode = 0;
    child.emit("close", 0);
    await closing;
  });

  it("force-SIGKILLs synchronously when killProcessTree's grace expires (#86412)", async () => {
    vi.useFakeTimers();
    const child = new MockChildProcess();
    spawnMock.mockReturnValue(child);

    const transport = new OpenClawStdioClientTransport({ command: "npx" });
    const started = transport.start();
    child.emit("spawn");
    await started;

    const closing = transport.close();
    await vi.advanceTimersByTimeAsync(2000);
    expect(killProcessTreeMock).toHaveBeenCalledWith(4321);
    expect(signalProcessTreeMock).not.toHaveBeenCalled();

    // killProcessTree's SIGKILL is .unref()'d (#86412); close() force-SIGKILLs
    // synchronously instead.
    await vi.advanceTimersByTimeAsync(2000);
    expect(signalProcessTreeMock).toHaveBeenCalledWith(4321, "SIGKILL");

    child.exitCode = 0;
    child.emit("close", 0);
    await closing;
  });

  it("force-closes an in-flight repeated graceful shutdown before returning", async () => {
    vi.useFakeTimers();
    const child = new MockChildProcess();
    spawnMock.mockReturnValue(child);

    const transport = new OpenClawStdioClientTransport({ command: "npx" });
    const started = transport.start();
    child.emit("spawn");
    await started;

    const closing = transport.close();
    const repeatedClose = transport.close();
    const forced = transport.forceClose();
    expect(signalProcessTreeMock).toHaveBeenCalledWith(4321, "SIGKILL");

    child.exitCode = 0;
    child.emit("close", 0);
    await expect(forced).resolves.toBeUndefined();
    await expect(closing).resolves.toBeUndefined();
    await expect(repeatedClose).resolves.toBeUndefined();
    expect(transport.pid).toBeNull();
  });

  it("does not kill the process tree when graceful stdio close exits", async () => {
    vi.useFakeTimers();
    const child = new MockChildProcess();
    spawnMock.mockReturnValue(child);

    const transport = new OpenClawStdioClientTransport({ command: "npx" });
    const started = transport.start();
    child.emit("spawn");
    await started;

    const closing = transport.close();
    child.exitCode = 0;
    child.emit("close", 0);
    await closing;

    expect(killProcessTreeMock).not.toHaveBeenCalled();
  });

  it("sends and receives JSON-RPC messages over stdio", async () => {
    const child = new MockChildProcess();
    spawnMock.mockReturnValue(child);

    const transport = new OpenClawStdioClientTransport({ command: "npx" });
    const onmessage = vi.fn();
    Object.assign(transport, { onmessage });
    const started = transport.start();
    child.emit("spawn");
    await started;

    await transport.send({ jsonrpc: "2.0", id: 1, method: "ping" });
    expect(child.stdin.read()?.toString()).toBe('{"jsonrpc":"2.0","id":1,"method":"ping"}\n');

    child.stdout.write('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n');
    expect(onmessage).toHaveBeenCalledWith({
      jsonrpc: "2.0",
      id: 1,
      result: { ok: true },
    });
  });

  it("rejects send() with EPIPE when child stdin is closed (#75438)", async () => {
    const child = new MockChildProcess();
    const brokenStdin = new PassThrough();
    brokenStdin.write = (_chunk: unknown, cbOrEncoding?: unknown, cb?: unknown) => {
      const callback =
        typeof cbOrEncoding === "function" ? cbOrEncoding : typeof cb === "function" ? cb : null;
      const err = Object.assign(new Error("write EPIPE"), { code: "EPIPE" });
      if (callback) {
        (callback as (err: Error) => void)(err);
      }
      return false;
    };
    child.stdin = brokenStdin;
    spawnMock.mockReturnValue(child);

    const transport = new OpenClawStdioClientTransport({ command: "npx" });
    const started = transport.start();
    child.emit("spawn");
    await started;

    await expect(transport.send({ jsonrpc: "2.0", id: 2, method: "ping" })).rejects.toThrow(
      "EPIPE",
    );
  });

  it("rejects send() when stdin.write throws synchronously (#75438)", async () => {
    const child = new MockChildProcess();
    const brokenStdin = new PassThrough();
    brokenStdin.write = () => {
      throw Object.assign(new Error("write after end"), { code: "ERR_STREAM_DESTROYED" });
    };
    child.stdin = brokenStdin;
    spawnMock.mockReturnValue(child);

    const transport = new OpenClawStdioClientTransport({ command: "npx" });
    const started = transport.start();
    child.emit("spawn");
    await started;

    await expect(transport.send({ jsonrpc: "2.0", id: 3, method: "ping" })).rejects.toThrow(
      "write after end",
    );
  });

  it("reports stderr pipe errors without an unhandled error crash", async () => {
    const child = new MockChildProcess();
    spawnMock.mockReturnValue(child);

    const transport = new OpenClawStdioClientTransport({ command: "npx", stderr: "pipe" });
    const onerror = vi.fn();
    Object.assign(transport, { onerror });
    const started = transport.start();
    child.emit("spawn");
    await started;

    const error = new Error("simulated pipe error");
    expect(() => child.stderr?.emit("error", error)).not.toThrow();
    expect(onerror).toHaveBeenCalledWith(error);

    child.stderr.write("server diagnostic");
    expect(transport.stderr?.read()?.toString()).toBe("server diagnostic");
  });

  it("rejects disallowed MCP server commands", async () => {
    expect(
      () => new OpenClawStdioClientTransport({ command: "/bin/bash", args: ["-c", "evil"] }),
    ).not.toThrow();
    // start() is where the command validation runs.
    const child = new MockChildProcess();
    spawnMock.mockReturnValue(child);
    const transport = new OpenClawStdioClientTransport({
      command: "/bin/bash",
      args: ["-c", "evil"],
    });
    await expect(transport.start()).rejects.toThrow("not allowed");
  });

  it.each(["node", "npx", "python3", "python", "uvx"])(
    "allows bare allowlisted command %s",
    async (command) => {
      const child = new MockChildProcess();
      spawnMock.mockReturnValue(child);

      const transport = new OpenClawStdioClientTransport({ command });
      const started = transport.start();
      child.emit("spawn");
      // Should resolve without error (command is in allowlist).
      await expect(started).resolves.toBeUndefined();
    },
  );

  it.each([
    ["/tmp/evil/node", "absolute path bypass"],
    ["./node", "relative path bypass"],
    ["../bin/node", "parent traversal bypass"],
    ["node.exe", ".exe must not match bare node"],
    ["", "empty command"],
    ["node\\\\x", "backslash path separator"],
    ["C:\\node.exe", "windows absolute path"],
    ["python/evil", "mid-string slash"],
  ])("rejects allowlist-bypassing command %s (%s)", async (command) => {
    const child = new MockChildProcess();
    spawnMock.mockReturnValue(child);
    const transport = new OpenClawStdioClientTransport({ command });
    await expect(transport.start()).rejects.toThrow("not allowed");
    // spawn() must never have been reached for a rejected command.
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("allows operator-added bare names via OPENCLAW_MCP_ALLOWED_COMMANDS", async () => {
    vi.stubEnv("OPENCLAW_MCP_ALLOWED_COMMANDS", "my-tool,another-tool");
    const child = new MockChildProcess();
    spawnMock.mockReturnValue(child);

    const transport = new OpenClawStdioClientTransport({ command: "my-tool" });
    const started = transport.start();
    child.emit("spawn");
    await expect(started).resolves.toBeUndefined();

    // Operators still cannot bypass the separator rule via env: a path-like
    // extra name is itself rejected at spawn time.
    const bypassChild = new MockChildProcess();
    spawnMock.mockReturnValue(bypassChild);
    const bypassTransport = new OpenClawStdioClientTransport({ command: "/tmp/my-tool" });
    await expect(bypassTransport.start()).rejects.toThrow("not allowed");

    vi.unstubAllEnvs();
  });

  it("allows npx MCP server commands", async () => {
    const child = new MockChildProcess();
    spawnMock.mockReturnValue(child);

    const transport = new OpenClawStdioClientTransport({ command: "npx" });
    const started = transport.start();
    child.emit("spawn");
    // Should resolve without error (command is in allowlist).
    await expect(started).resolves.toBeUndefined();
  });
});
