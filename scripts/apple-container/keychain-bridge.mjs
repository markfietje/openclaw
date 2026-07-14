#!/usr/bin/env node
import { execFile } from "node:child_process";
import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
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

const allowedClientCidrs = (process.env.OPENCLAW_KEYCHAIN_BRIDGE_ALLOWED_CIDRS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// Optional per-ID secret map. When present, each entry maps a secret id to a
// distinct macOS Keychain item (service + optional account). This lets the
// bridge back arbitrary secrets (e.g. model provider API keys) without them
// ever touching the container volume. IDs absent from the map continue to
// resolve to the default gateway-token keychain item.
const secretMapPath = process.env.OPENCLAW_KEYCHAIN_SECRET_MAP_FILE || "";
const secretMap = (() => {
  if (!secretMapPath) return {};
  try {
    const raw = readFileSync(secretMapPath, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      console.error(`OPENCLAW_KEYCHAIN_SECRET_MAP_FILE is not a JSON object: ${secretMapPath}`);
      process.exit(1);
    }
    const normalized = {};
    for (const [id, entry] of Object.entries(parsed)) {
      if (typeof id !== "string" || !id) continue;
      if (
        !entry ||
        typeof entry !== "object" ||
        typeof entry.service !== "string" ||
        !entry.service
      ) {
        console.error(`Invalid secret map entry for id "${id}": expected {service, account?}`);
        process.exit(1);
      }
      normalized[id] = {
        service: entry.service,
        account: typeof entry.account === "string" && entry.account ? entry.account : account,
      };
    }
    return normalized;
  } catch (error) {
    console.error(
      `Failed to read OPENCLAW_KEYCHAIN_SECRET_MAP_FILE (${secretMapPath}): ${error.message}`,
    );
    process.exit(1);
  }
})();

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

async function readKeychainItem(serviceName, accountName) {
  const { stdout } = await execFileAsync(
    "/usr/bin/security",
    ["find-generic-password", "-a", accountName, "-s", serviceName, "-w"],
    {
      encoding: "utf8",
      maxBuffer: 16 * 1024,
      timeout: keychainTimeoutMs,
      windowsHide: true,
    },
  );
  const value = stdout.trim();
  if (!value) {
    throw new Error(`keychain item is empty for service=${serviceName} account=${accountName}`);
  }
  return value;
}

// Resolves the default gateway-token keychain item. Preserved verbatim for
// backward compatibility with existing gateway-token / value callers.
async function readGatewayTokenFromKeychain() {
  return await readKeychainItem(service, account);
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

  // Allow IDs that are either explicitly allowlisted (gateway/token, value)
  // or declared in the optional secret map. Map IDs are safe to expose because
  // each resolves to its own keychain item, chosen by the operator.
  const requestedIds = payload.ids
    .filter((id) => typeof id === "string" && (allowedIds.has(id) || Object.hasOwn(secretMap, id)))
    .slice(0, allowedIds.size + Object.keys(secretMap).length);
  if (requestedIds.length === 0) {
    sendJson(response, 200, { protocolVersion: 1, values: {} });
    return;
  }

  try {
    const values = {};
    // Preserve the original gateway-token behavior: gateway/token and value
    // both resolve to the default keychain item. Per-ID mapped secrets use
    // their own keychain service via the optional secret map.
    for (const id of requestedIds) {
      if (id === "gateway/token" || id === "value") {
        values[id] = await readGatewayTokenFromKeychain();
      } else if (secretMap[id]) {
        values[id] = await readKeychainItem(secretMap[id].service, secretMap[id].account);
      }
    }
    sendJson(response, 200, { protocolVersion: 1, values });
  } catch (error) {
    console.error(error && error.message ? error.message : String(error));
    sendJson(response, 503, { error: "keychain unavailable" });
  }
}

// IP allowlist: reject connections from outside permitted CIDRs.
// Loopback (127.0.0.0/8, ::1/128) is always allowed.
// OPENCLAW_KEYCHAIN_BRIDGE_ALLOWED_CIDRS adds container-network ranges.
const { isIPv4, isIPv6 } = await import("node:net");

function ipToBuffer(ip) {
  if (isIPv4(ip)) {
    return Buffer.from(
      ip.split(".").map((octet) => {
        const n = Number.parseInt(octet, 10);
        return n;
      }),
    );
  }
  if (isIPv6(ip)) {
    // Expand :: shorthand to 16 bytes
    const expanded = ip.replace("::", ":".repeat(9 - ip.split(":").length));
    return Buffer.from(
      expanded.split(":").flatMap((h) => {
        const val = Number.parseInt(h || "0", 16);
        return [(val >> 8) & 0xff, val & 0xff];
      }),
    );
  }
  return null;
}

function parseCidr(cidr) {
  const [ip, bitsStr] = cidr.split("/");
  const bits = Number(bitsStr);
  const buf = ipToBuffer(ip);
  if (!buf || Number.isNaN(bits) || bits < 0 || bits > buf.length * 8) return null;
  const mask =
    bits === 0
      ? Buffer.alloc(buf.length, 0)
      : Buffer.from(
          Array.from(
            { length: buf.length },
            (_, i) => ((0xff << (8 - Math.min(8, Math.max(0, bits - i * 8)))) & 0xff) >>> 0,
          ),
        );
  return { network: Buffer.from(buf.map((b, i) => b & mask[i])), mask };
}

const parsedCidrs = allowedClientCidrs.map(parseCidr).filter(Boolean);

function isLoopback(ip) {
  return ip === "127.0.0.1" || ip === "::1" || ip.startsWith("127.");
}

function isIpAllowed(ip) {
  if (isLoopback(ip)) return true;
  if (parsedCidrs.length === 0) return true; // no CIDR filter = allow all (backward compat)
  const buf = ipToBuffer(ip);
  if (!buf) return false;
  return parsedCidrs.some((cidr) => {
    if (cidr.network.length !== buf.length) return false;
    const masked = Buffer.from(buf.map((b, i) => b & cidr.mask[i]));
    return masked.equals(cidr.network);
  });
}

const server = createServer((request, response) => {
  // Enforce IP allowlist before any handler runs
  const clientIp = request.socket.remoteAddress;
  if (clientIp && !isIpAllowed(clientIp)) {
    console.error(`[bridge] Rejected connection from ${clientIp} (not in allowed CIDRs)`);
    sendJson(response, 403, { error: "forbidden" });
    request.socket.destroy();
    return;
  }
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

server.listen(port, host, () => {
  void (async () => {
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
    console.error(
      `OpenClaw Keychain bridge listening on ${host}:${selectedPort}` +
        (parsedCidrs.length > 0
          ? ` (allowed CIDRs: loopback + ${allowedClientCidrs.join(", ")})`
          : " (no CIDR filter — allow all)"),
    );
  })();
});
