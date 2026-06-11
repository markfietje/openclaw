// SSE heartbeat keeps reverse-proxy connections alive during model thinking.
// Writes an SSE comment frame (ignored by spec-compliant clients) at a fixed interval.

import type { ServerResponse } from "node:http";

const SSE_HEARTBEAT_INTERVAL_MS = 15_000;

export function startSseHeartbeat(res: ServerResponse): () => void {
  const heartbeat = setInterval(() => {
    if (!res.writableEnded) {
      res.write(": heartbeat\n\n");
    }
  }, SSE_HEARTBEAT_INTERVAL_MS);
  heartbeat.unref();
  const cleanup = () => clearInterval(heartbeat);
  res.once("close", cleanup);
  return cleanup;
}
