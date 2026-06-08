// Gateway Client module implements device auth behavior.
// OWASP A05:2021 — Security Logging/Monitoring Failures. Enforce maximum
// field length to prevent memory exhaustion via oversized device metadata.
const MAX_DEVICE_METADATA_LENGTH = 128;

export function normalizeDeviceMetadataForAuth(value?: string | null): string {
  if (typeof value !== "string") {
    return "";
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return "";
  }
  // Truncate to maximum length to prevent memory exhaustion.
  const truncated =
    trimmed.length > MAX_DEVICE_METADATA_LENGTH
      ? trimmed.slice(0, MAX_DEVICE_METADATA_LENGTH)
      : trimmed;
  return truncated.replace(/[A-Z]/g, (char) => String.fromCharCode(char.charCodeAt(0) + 32));
}

type DeviceAuthPayloadParams = {
  deviceId: string;
  clientId: string;
  clientMode: string;
  role: string;
  scopes: string[];
  signedAtMs: number;
  token?: string | null;
  nonce: string;
};

type DeviceAuthPayloadV3Params = DeviceAuthPayloadParams & {
  platform?: string | null;
  deviceFamily?: string | null;
};

export function buildDeviceAuthPayload(params: DeviceAuthPayloadParams): string {
  const scopes = params.scopes.join(",");
  const token = params.token ?? "";
  return [
    "v2",
    params.deviceId,
    params.clientId,
    params.clientMode,
    params.role,
    scopes,
    String(params.signedAtMs),
    token,
    params.nonce,
  ].join("|");
}

export function buildDeviceAuthPayloadV3(params: DeviceAuthPayloadV3Params): string {
  const scopes = params.scopes.join(",");
  const token = params.token ?? "";
  // Device signatures are byte-for-byte compared by the gateway. Normalize
  // optional metadata before joining so case differences do not break auth.
  const platform = normalizeDeviceMetadataForAuth(params.platform);
  const deviceFamily = normalizeDeviceMetadataForAuth(params.deviceFamily);
  return [
    "v3",
    params.deviceId,
    params.clientId,
    params.clientMode,
    params.role,
    scopes,
    String(params.signedAtMs),
    token,
    params.nonce,
    platform,
    deviceFamily,
  ].join("|");
}
