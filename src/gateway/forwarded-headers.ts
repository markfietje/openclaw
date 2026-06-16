export interface ForwardedHeader {
  for?: string;
  by?: string;
  host?: string;
  proto?: string;
}

export function validateProtoMismatch(params: {
  originProto: string;
  forwardedProto?: string;
  xForwardedProto?: string | string[];
}): { ok: true } | { ok: false; reason: string } {
  const { originProto, forwardedProto, xForwardedProto } = params;

  const originNormalized = originProto.toLowerCase();

  if (forwardedProto) {
    const forwardedNormalized = forwardedProto.toLowerCase();
    if (originNormalized !== forwardedNormalized) {
      return {
        ok: false,
        reason: `origin protocol (${originProto}) does not match Forwarded proto (${forwardedProto})`,
      };
    }
  }

  if (xForwardedProto) {
    const raw = Array.isArray(xForwardedProto) ? xForwardedProto[0] : xForwardedProto;
    if (raw) {
      const xNormalized = raw.trim().toLowerCase();
      if (originNormalized !== xNormalized) {
        return {
          ok: false,
          reason: `origin protocol (${originProto}) does not match X-Forwarded-Proto (${raw})`,
        };
      }
    }
  }

  return { ok: true };
}
