#!/usr/bin/env node
import { execFile } from "node:child_process";
import { timingSafeEqual } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const host = process.env.OPENCLAW_KEYCHAIN_BRIDGE_HOST || "127.0.0.1";
const port = Number(process.env.OPENCLAW_KEYCHAIN_BRIDGE_PORT || "0");
const portFile = process.env.OPENCLAW_KEYCHAIN_BRIDGE_PORT_FILE || "";
const pidFile = process.env.OPENCLAW_KEYCHAIN_BRIDGE_PID_FILE || "";
const authToken = process.env.OPENCLAW_KEYCHAIN_BRIDGE_TOKEN || "";
const service =
  process.env.OPENCLAW_KEYCHAIN_SERVICE || "ai.openclaw.apple-container.gateway-token";
const account = process.env.OPENCLAW_KEYCHAIN_ACCOUNT || process.env.USER || "openclaw";
const maxBodyBytes = Number(process.env.OPENCLAW_KEYCHAIN_BRIDGE_MAX_BODY_BYTES || "8192");
const keychainTimeoutMs = Number(
  process.env.OPENCLAW_KEYCHAIN_BRIDGE_KEYCHAIN_TIMEOUT_MS || "15000",
);
const allowedIds = new Set(
  (process.env.OPENCLAW_KEYCHAIN_ALLOWED_IDS || "gateway/token,value")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean),
);

if (!authToken) {
  console.error("OPENCLAW_KEYCHAIN_BRIDGE_TOKEN is required.");
  process.exit(1);
}

if (!Number.isInteger(port) || port < 0 || port > 65535) {
  console.error("OPENCLAW_KEYCHAIN_BRIDGE_PORT must be between 0 and 65535.");
  process.exit(1);
}

if (!Number.isInteger(maxBodyBytes) || maxBodyBytes < 1 || maxBodyBytes > 1024 * 1024) {
  console.error("OPENCLAW_KEYCHAIN_BRIDGE_MAX_BODY_BYTES must be between 1 and 1048576.");
  process.exit(1);
}

if (!Number.isInteger(keychainTimeoutMs) || keychainTimeoutMs < 1000 || keychainTimeoutMs > 60000) {
  console.error("OPENCLAW_KEYCHAIN_BRIDGE_KEYCHAIN_TIMEOUT_MS must be between 1000 and 60000.");
  process.exit(1);
}

function isAuthorized(header) {
  if (typeof header !== "string" || !header.startsWith("Bearer ")) {
    return false;
  }
  const received = Buffer.from(header.slice("Bearer ".length));
  const expected = Buffer.from(authToken);
  return received.length === expected.length && timingSafeEqual(received, expected);
}

function sendJson(response, status, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(body),
  });
  response.end(body);
}

function unauthorized(response) {
  sendJson(response, 401, { error: "unauthorized" });
}

async function readRequestBody(request) {
  return await new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > maxBodyBytes) {
        reject(new Error("request too large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}

async function readGatewayTokenFromKeychain() {
  const { stdout } = await execFileAsync(
    "/usr/bin/security",
    ["find-generic-password", "-a", account, "-s", service, "-w"],
    {
      encoding: "utf8",
      maxBuffer: 16 * 1024,
      timeout: keychainTimeoutMs,
      windowsHide: true,
    },
  );
  const token = stdout.trim();
  if (!token) {
    throw new Error("keychain item is empty");
  }
  return token;
}

async function handleSecretRequest(request, response) {
  if (!isAuthorized(request.headers.authorization)) {
    unauthorized(response);
    return;
  }

  let payload;
  try {
    payload = JSON.parse(await readRequestBody(request));
  } catch {
    sendJson(response, 400, { error: "invalid request" });
    return;
  }

  if (payload?.protocolVersion !== 1 || !Array.isArray(payload.ids)) {
    sendJson(response, 400, { error: "invalid request" });
    return;
  }

  const requestedIds = payload.ids
    .filter((id) => typeof id === "string" && allowedIds.has(id))
    .slice(0, allowedIds.size);
  if (requestedIds.length === 0) {
    sendJson(response, 200, { protocolVersion: 1, values: {} });
    return;
  }

  try {
    const token = await readGatewayTokenFromKeychain();
    const values = Object.fromEntries(requestedIds.map((id) => [id, token]));
    sendJson(response, 200, { protocolVersion: 1, values });
  } catch (error) {
    console.error(error && error.message ? error.message : String(error));
    sendJson(response, 503, { error: "keychain unavailable" });
  }
}

const server = createServer((request, response) => {
  if (request.method === "GET" && request.url === "/healthz") {
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && request.url === "/secret") {
    void handleSecretRequest(request, response);
    return;
  }
  sendJson(response, 404, { error: "not found" });
});

server.on("clientError", (_error, socket) => {
  socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
});

server.listen(port, host, async () => {
  const address = server.address();
  const selectedPort = typeof address === "object" && address ? address.port : port;
  if (portFile) {
    await mkdir(dirname(portFile), { recursive: true, mode: 0o700 });
    await writeFile(portFile, `${selectedPort}\n`, { mode: 0o600 });
  }
  if (pidFile) {
    await mkdir(dirname(pidFile), { recursive: true, mode: 0o700 });
    await writeFile(pidFile, `${process.pid}\n`, { mode: 0o600 });
  }
  console.error(`OpenClaw Keychain bridge listening on ${host}:${selectedPort}`);
});
