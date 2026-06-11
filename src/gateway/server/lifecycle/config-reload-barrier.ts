// Config reload barrier for gateway dispatch coordination.
// When a hot-reload plan affects runtime state, the barrier is set so inflight
// RPCs either await or reject with UNAVAILABLE.

type BarrierState = {
  promise: Promise<void>;
  resolve: () => void;
};

let activeBarrier: BarrierState | null = null;

export function isConfigReloadBarrierActive(): boolean {
  return activeBarrier !== null;
}

export function getConfigReloadBarrier(): Promise<void> | null {
  return activeBarrier?.promise ?? null;
}

export function setConfigReloadBarrier(_reason: string): { release: () => void } {
  if (activeBarrier) {
    activeBarrier.resolve();
  }
  let resolveFn!: () => void;
  const promise = new Promise<void>((resolve) => {
    resolveFn = resolve;
  });
  activeBarrier = { promise, resolve: resolveFn };
  return {
    release() {
      if (activeBarrier?.promise === promise) {
        activeBarrier.resolve();
        activeBarrier = null;
      }
    },
  };
}

export function clearConfigReloadBarrier(): void {
  if (activeBarrier) {
    activeBarrier.resolve();
    activeBarrier = null;
  }
}
