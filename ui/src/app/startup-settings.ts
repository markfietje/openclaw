// Control UI startup settings resolve native auth handoff and URL parameters.
import { normalizeOptionalString } from "../lib/string-coerce.ts";
import type { UiSettings } from "./settings.ts";

type ApplicationStartupLocation = {
  pathname: string;
  search: string;
  hash: string;
};

type NativeControlAuth = {
  gatewayUrl?: string | null;
  token?: string | null;
  password?: string | null;
};

type ApplicationStartupSettings = {
  settings: UiSettings;
  password: string | null;
  pendingGatewayUrl: string | null;
  pendingGatewayToken: string | null;
  pendingBootstrapToken: string | null;
  queryTokenUsed: boolean;
  location: ApplicationStartupLocation;
  changed: boolean;
};

declare global {
  interface Window {
    __OPENCLAW_NATIVE_CONTROL_AUTH__?: NativeControlAuth;
  }
}

/**
 * Returns true when a deep-link gateway URL points at the Control UI's own
 * /gateway endpoint on the same origin. Such links are applied directly
 * (with any accompanying token) instead of routing through the cross-origin
 * confirmation flow. Reads the global `location` (window.location in the
 * browser) rather than the injected startup location, since the comparison is
 * inherently a browser-environment concern.
 */
function isSameOriginGatewayEndpoint(gatewayUrl: string): boolean {
  if (typeof location === "undefined" || !location.protocol || !location.host) {
    return false;
  }
  try {
    const pageUrl = new URL(`${location.protocol}//${location.host}`);
    const parsedGatewayUrl = new URL(gatewayUrl, pageUrl);
    if (parsedGatewayUrl.protocol !== "ws:" && parsedGatewayUrl.protocol !== "wss:") {
      return false;
    }
    const gatewayPath = parsedGatewayUrl.pathname.replace(/\/+$/, "") || "/";
    return parsedGatewayUrl.host === pageUrl.host && gatewayPath === "/gateway";
  } catch {
    return false;
  }
}

export function resolveApplicationStartupSettings(
  initialSettings: UiSettings,
  location: ApplicationStartupLocation,
): ApplicationStartupSettings {
  let settings = initialSettings;
  let changed = false;
  let password: string | null = null;
  let pendingGatewayUrl: string | null = null;
  let pendingGatewayToken: string | null = null;
  let pendingBootstrapToken: string | null = null;
  let queryTokenUsed = false;

  const updateSettings = (patch: Partial<UiSettings>) => {
    const entries = Object.entries(patch) as Array<
      [keyof UiSettings, UiSettings[keyof UiSettings]]
    >;
    if (entries.every(([key, value]) => settings[key] === value)) {
      return;
    }
    settings = { ...settings, ...patch };
    changed = true;
  };

  const nativeAuth =
    typeof window === "undefined" ? undefined : window["__OPENCLAW_NATIVE_CONTROL_AUTH__"];
  if (nativeAuth) {
    try {
      delete window["__OPENCLAW_NATIVE_CONTROL_AUTH__"];
    } catch {
      window["__OPENCLAW_NATIVE_CONTROL_AUTH__"] = undefined;
    }

    const gatewayUrl = normalizeOptionalString(nativeAuth.gatewayUrl);
    const token = normalizeOptionalString(nativeAuth.token);
    const nativePassword = normalizeOptionalString(nativeAuth.password);
    updateSettings({
      ...(gatewayUrl ? { gatewayUrl } : {}),
      ...(token ? { token } : {}),
    });
    if (nativePassword) {
      password = nativePassword;
    }
  }

  if (!location.search && !location.hash) {
    return {
      settings,
      password,
      pendingGatewayUrl,
      pendingGatewayToken,
      pendingBootstrapToken,
      queryTokenUsed,
      location,
      changed,
    };
  }

  const url = new URL(
    `${location.pathname}${location.search}${location.hash}`,
    "http://openclaw.local",
  );
  const params = new URLSearchParams(url.search);
  const hashParams = new URLSearchParams(url.hash.startsWith("#") ? url.hash.slice(1) : url.hash);
  const gatewayUrlRaw = params.get("gatewayUrl") ?? hashParams.get("gatewayUrl");
  const nextGatewayUrl = normalizeOptionalString(gatewayUrlRaw) ?? "";
  const gatewayUrlChanged = Boolean(nextGatewayUrl && nextGatewayUrl !== settings.gatewayUrl);
  // Same-origin /gateway deep links are applied directly; only cross-origin or
  // non-/gateway changes route through pendingGatewayUrl + confirmation.
  const shouldConfirmGatewayUrlChange = Boolean(
    gatewayUrlChanged && !isSameOriginGatewayEndpoint(nextGatewayUrl),
  );
  const queryToken = params.get("token");
  const hashToken = hashParams.get("token");
  const hasTokenParam = hashToken != null || queryToken != null;
  const token = normalizeOptionalString(hashToken ?? queryToken);
  const hasBootstrapTokenParam = hashParams.has("bootstrapToken");
  const bootstrapToken = normalizeOptionalString(hashParams.get("bootstrapToken"));
  const session = normalizeOptionalString(params.get("session") ?? hashParams.get("session"));
  // Reset session only when the token is genuinely new (e.g., a deep link from
  // another device). When native Mac auth has already applied the same keychain
  // token, or the token matches what is already persisted, the user's last
  // session should be preserved.
  const shouldResetSessionForToken = Boolean(
    token && !session && !shouldConfirmGatewayUrlChange && token !== settings.token,
  );
  let shouldCleanUrl = false;

  if (params.has("token")) {
    params.delete("token");
    shouldCleanUrl = true;
  }

  if (hasTokenParam) {
    if (queryToken != null) {
      queryTokenUsed = true;
      console.warn(
        "[openclaw] Auth token passed as query parameter (?token=). Use URL fragment instead: #token=<token>. Query parameters may appear in server logs.",
      );
    }
    if (token && shouldConfirmGatewayUrlChange) {
      pendingGatewayToken = token;
    } else if (token) {
      updateSettings({ token });
    }
    hashParams.delete("token");
    shouldCleanUrl = true;
  }

  if (hasBootstrapTokenParam) {
    pendingBootstrapToken = bootstrapToken ?? null;
    hashParams.delete("bootstrapToken");
    shouldCleanUrl = true;
  }

  if (shouldResetSessionForToken) {
    updateSettings({
      sessionKey: "main",
      lastActiveSessionKey: "main",
    });
  }

  if (params.has("password") || hashParams.has("password")) {
    params.delete("password");
    hashParams.delete("password");
    shouldCleanUrl = true;
  }

  if (session) {
    updateSettings({
      sessionKey: session,
      lastActiveSessionKey: session,
    });
  }

  if (gatewayUrlRaw != null) {
    if (shouldConfirmGatewayUrlChange) {
      pendingGatewayUrl = nextGatewayUrl;
      // pendingGatewayToken, if any, was already staged in the token block.
    } else {
      pendingGatewayUrl = null;
      pendingGatewayToken = null;
      if (gatewayUrlChanged) {
        // Same-origin /gateway endpoint: apply directly with any token.
        updateSettings({
          gatewayUrl: nextGatewayUrl,
          ...(token ? { token } : {}),
        });
      }
    }
    params.delete("gatewayUrl");
    hashParams.delete("gatewayUrl");
    shouldCleanUrl = true;
  }

  if (shouldCleanUrl) {
    url.search = params.toString();
    const nextHash = hashParams.toString();
    url.hash = nextHash ? `#${nextHash}` : "";
  }

  return {
    settings,
    password,
    pendingGatewayUrl,
    pendingGatewayToken,
    pendingBootstrapToken,
    queryTokenUsed,
    location: shouldCleanUrl
      ? {
          pathname: url.pathname,
          search: url.search,
          hash: url.hash,
        }
      : location,
    changed,
  };
}
