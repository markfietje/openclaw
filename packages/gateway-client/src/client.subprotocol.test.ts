import { createServer } from "node:net";
import { afterEach, describe, expect, test } from "vitest";
import { WebSocketServer } from "ws";
import { GatewayClient } from "./client.js";

async function getFreePort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const server = createServer();
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as { port: number }).port;
      server.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

describe("GatewayClient subprotocol", () => {
  let wss: WebSocketServer | null = null;

  afterEach(async () => {
    if (wss) {
      for (const client of wss.clients) {
        client.terminate();
      }
      await new Promise<void>((resolve) => {
        wss?.close(() => resolve());
      });
      wss = null;
    }
  });

  test("sends openclaw-gateway-v1 as Sec-WebSocket-Protocol", async () => {
    const port = await getFreePort();

    const receivedProtocol = await new Promise<string | undefined>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("timed out waiting for upgrade")), 5_000);

      wss = new WebSocketServer({ port, host: "127.0.0.1" });
      wss.on("connection", (socket) => {
        clearTimeout(timeout);
        // socket.protocol is the negotiated subprotocol sent by the client.
        resolve(socket.protocol);
        socket.terminate();
      });

      const client = new GatewayClient({
        url: `ws://127.0.0.1:${port}`,
        connectChallengeTimeoutMs: 0,
        onConnectError: (err) => {
          clearTimeout(timeout);
          reject(err);
        },
      });
      client.start();
    });

    // The ws library requires the subprotocol as the second constructor argument.
    // Passing `protocol` inside the options object is silently ignored and results
    // in an undefined Sec-WebSocket-Protocol header.
    expect(receivedProtocol).toBe("openclaw-gateway-v1");
  });
});
