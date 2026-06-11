// Centralized timer registry.
// Tracks setTimeout/setInterval handles so shutdown can clear them in one pass
// and .unref() prevents them from keeping the process alive.

type TimerHandle = ReturnType<typeof setTimeout> | ReturnType<typeof setInterval>;

const timers = new Map<string, TimerHandle>();

function register(id: string, handle: TimerHandle): TimerHandle {
  const existing = timers.get(id);
  if (existing !== undefined) {
    clearTimeout(existing as ReturnType<typeof setTimeout>);
    clearInterval(existing as ReturnType<typeof setInterval>);
  }
  if (
    typeof (handle as ReturnType<typeof setInterval> & { unref?: () => void }).unref === "function"
  ) {
    (handle as ReturnType<typeof setInterval> & { unref: () => void }).unref();
  }
  timers.set(id, handle);
  return handle;
}

export function registerInterval(
  id: string,
  fn: () => void,
  ms: number,
): ReturnType<typeof setInterval> {
  return register(id, setInterval(fn, ms));
}

export function registerTimeout(
  id: string,
  fn: () => void,
  ms: number,
): ReturnType<typeof setTimeout> {
  return register(id, setTimeout(fn, ms));
}

export function clearAllTimers(): void {
  for (const handle of timers.values()) {
    clearTimeout(handle as ReturnType<typeof setTimeout>);
    clearInterval(handle as ReturnType<typeof setInterval>);
  }
  timers.clear();
}

export function getRegisteredTimerCount(): number {
  return timers.size;
}
