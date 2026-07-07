// Ambient declarations for scripts/tsdown-build.mjs consumed by tests.
// Param types are intentionally loose (unknown for fs/spawn-like injectable
// deps and mock child handles) so test doubles satisfy the signatures, mirroring
// the style of scripts/run-node.d.mts.

export type TsdownBuildInvocationOptions = {
  stdio?: unknown;
  shell?: boolean;
  windowsVerbatimArguments?: boolean;
  env: NodeJS.ProcessEnv;
};

export type TsdownBuildInvocation = {
  command: string;
  args: string[];
  options: TsdownBuildInvocationOptions;
};

export type TsdownBuildInvocationParams = {
  args?: string[];
  env?: NodeJS.ProcessEnv;
  nodeExecPath?: string;
  npmExecPath?: string;
  comSpec?: string;
  platform?: NodeJS.Platform;
  cgroupMemoryLimitPaths?: string[];
  cgroupMemoryLimitBytes?: number;
  procMeminfoPath?: string;
  fs?: unknown;
};

export type TsdownBuildParsedArgs = {
  forwardedArgs: string[];
  stage: string;
  help: boolean;
};

export type TsdownOutputScannerFinishResult = {
  captured: string;
  hasIneffectiveDynamicImport: boolean;
  fatalUnresolvedImport: string | null;
};

export type TsdownOutputScanner = {
  append(chunk: string | Buffer): void;
  finish(): TsdownOutputScannerFinishResult;
};

export type TsdownBuildRunParams = {
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  cwd?: string;
  stdout?: { write: (value: string) => void };
  stderr?: { write: (value: string) => void };
  scanner?: TsdownOutputScanner;
  spawn?: unknown;
  spawnSync?: unknown;
  runTaskkill?: unknown;
};

export type TsdownBuildRunResult = {
  status: number | null;
  signal: NodeJS.Signals | null;
  timedOut: boolean;
  hasIneffectiveDynamicImport: boolean;
  fatalUnresolvedImport: string | null;
  stdout: string;
  stderr: string;
};

export function cleanTsdownOutputRoots(params?: {
  cwd?: string;
  fs?: unknown;
  env?: NodeJS.ProcessEnv;
}): void;

export function pruneStaleRootChunkFiles(params?: {
  cwd?: string;
  fs?: unknown;
}): void;

export function listTsdownOutputRoots(): string[];

export function pruneUntrackedGeneratedSourceDeclarations(params?: {
  cwd?: string;
  fs?: unknown;
  spawnSync?: unknown;
}): number;

export function pruneSourceCheckoutBundledPluginNodeModules(params?: {
  cwd?: string;
  logger?: unknown;
  packageRoot?: string;
  fs?: unknown;
}): void;

export function tsdownBuildUsage(): string;

export function parseTsdownBuildArgs(argv: string[]): TsdownBuildParsedArgs;

export function createTsdownOutputScanner(params?: {
  maxCaptureBytes?: number;
}): TsdownOutputScanner;

export function resolveTsdownBuildInvocation(
  params?: TsdownBuildInvocationParams,
): TsdownBuildInvocation;

export function resolveTsdownBuildInvocations(
  params?: TsdownBuildInvocationParams,
): TsdownBuildInvocation[];

export function signalTsdownBuildProcessTree(
  child: { pid?: number | null; kill?: (signal?: NodeJS.Signals | number) => boolean | void },
  signal: NodeJS.Signals | number,
  options?: {
    platform?: NodeJS.Platform;
    runTaskkill?: unknown;
    useProcessGroup?: boolean;
  },
): void;

export function runTsdownBuildInvocation(
  invocation: TsdownBuildInvocation,
  params?: TsdownBuildRunParams,
): Promise<TsdownBuildRunResult>;
