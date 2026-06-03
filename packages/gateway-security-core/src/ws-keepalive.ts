/**
 * WebSocket ping/pong keep-alive with dead connection detection.
 *
 * Sends periodic ping frames and tracks pong responses. If no pong is received
 * within the timeout window, the connection is terminated as dead.
 *
 * @see FORK_SECURITY.md § Operational Hardening — Ping/pong keep-alive
 */

export interface WsKeepaliveConfig {
  /** Interval between ping frames in ms. @default 25_000 */
  pingIntervalMs?: number;
  /** Time to wait for pong response before closing in ms. @default 10_000 */
  pongTimeoutMs?: number;
}

export interface WsKeepaliveHandlers {
  /** Send a ping frame. */
  ping: () => void;
  /** Close the connection (optionally with code and reason). */
  close: () => void;
  /** Log a warning message. */
  warn: (msg: string) => void;
}

export interface WsKeepalive {
  /** Start the keep-alive timers. */
  start(): void;
  /** Stop all timers (call on connection close). */
  stop(): void;
  /** Record a pong reception (call from the 'pong' event handler). */
  onPong(): void;
}

export function createWsKeepalive(
  config: WsKeepaliveConfig,
  handlers: WsKeepaliveHandlers,
): WsKeepalive {
  const pingIntervalMs = config.pingIntervalMs ?? 25_000;
  const pongTimeoutMs = config.pongTimeoutMs ?? 10_000;

  let pingTimer: ReturnType<typeof setInterval> | null = null;
  let pongTimer: ReturnType<typeof setTimeout> | null = null;
  let running = false;

  function schedulePongTimeout() {
    if (pongTimer !== null) {
      clearTimeout(pongTimer);
    }
    pongTimer = setTimeout(() => {
      if (!running) {
        return;
      }
      handlers.warn(`pong timeout after ${pongTimeoutMs}ms — closing dead connection`);
      handlers.close();
    }, pongTimeoutMs);
  }

  function start() {
    if (running) {
      return;
    }
    running = true;
    pingTimer = setInterval(() => {
      if (!running) {
        return;
      }
      try {
        handlers.ping();
        schedulePongTimeout();
      } catch {
        // Socket may already be closing.
      }
    }, pingIntervalMs);
  }

  function stop() {
    running = false;
    if (pingTimer !== null) {
      clearInterval(pingTimer);
      pingTimer = null;
    }
    if (pongTimer !== null) {
      clearTimeout(pongTimer);
      pongTimer = null;
    }
  }

  function onPong() {
    if (pongTimer !== null) {
      clearTimeout(pongTimer);
      pongTimer = null;
    }
  }

  return { start, stop, onPong };
}
