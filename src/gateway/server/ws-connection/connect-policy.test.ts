// WebSocket connect-policy tests cover Control UI pairing, trusted proxy auth, and device identity policy.
import { describe, expect, test } from "vitest";
import { isBrowserOperatorUiClient } from "../../../utils/message-channel.js";
import {
  evaluateMissingDeviceIdentity,
  isTrustedProxyControlUiOperatorAuth,
  resolveControlUiAuthPolicy,
  shouldClearUnboundScopesForMissingDeviceIdentity,
  shouldSkipControlUiPairing,
} from "./connect-policy.js";

type ControlUiAuthPolicyInput = Parameters<typeof resolveControlUiAuthPolicy>[0];
type DeviceRaw = NonNullable<ControlUiAuthPolicyInput["deviceRaw"]>;
type MissingDeviceIdentityInput = Parameters<typeof evaluateMissingDeviceIdentity>[0];
type MissingDeviceDecisionKind = ReturnType<typeof evaluateMissingDeviceIdentity>["kind"];
type PairingRole = Parameters<typeof shouldSkipControlUiPairing>[1];
type PairingAuthMode = Parameters<typeof shouldSkipControlUiPairing>[3];
type PairingAuthMethod = Parameters<typeof shouldSkipControlUiPairing>[4];
type ClearUnboundScopesInput = Parameters<
  typeof shouldClearUnboundScopesForMissingDeviceIdentity
>[0];

function deviceRaw(id: string): DeviceRaw {
  return {
    id,
    publicKey: "pk",
    signature: "sig",
    signedAt: Date.now(),
    nonce: `${id}-nonce`,
  };
}

function authPolicy(params: Partial<ControlUiAuthPolicyInput> = {}) {
  return resolveControlUiAuthPolicy({
    isControlUi: params.isControlUi ?? false,
    controlUiConfig: params.controlUiConfig,
    deviceRaw: params.deviceRaw ?? null,
  });
}

function expectMissingDeviceDecision(
  overrides: Partial<MissingDeviceIdentityInput>,
  expected: MissingDeviceDecisionKind,
) {
  const isControlUi = overrides.isControlUi ?? false;
  const params: MissingDeviceIdentityInput = {
    hasDeviceIdentity: false,
    role: "operator",
    isControlUi,
    controlUiAuthPolicy: overrides.controlUiAuthPolicy ?? authPolicy({ isControlUi }),
    trustedProxyAuthOk: false,
    sharedAuthOk: true,
    authOk: true,
    hasSharedAuth: true,
    isLocalClient: false,
    ...overrides,
  };
  expect(evaluateMissingDeviceIdentity(params).kind).toBe(expected);
}

function expectSkipPairing(
  policy: Parameters<typeof shouldSkipControlUiPairing>[0],
  role: PairingRole,
  expected: boolean,
  params: {
    pairingComplete?: boolean;
    authMode?: PairingAuthMode;
    authMethod?: PairingAuthMethod;
  } = {},
) {
  expect(
    shouldSkipControlUiPairing(
      policy,
      role,
      params.pairingComplete ?? false,
      params.authMode,
      params.authMethod,
    ),
  ).toBe(expected);
}

function expectClearsUnboundScopes(overrides: Partial<ClearUnboundScopesInput>, expected: boolean) {
  const params: ClearUnboundScopesInput = {
    decision: { kind: "allow" },
    controlUiAuthPolicy: authPolicy(),
    preserveInsecureLocalControlUiScopes: false,
    authMethod: "token",
    ...overrides,
  };
  expect(shouldClearUnboundScopesForMissingDeviceIdentity(params)).toBe(expected);
}

describe("ws connect policy", () => {
  test("resolves control-ui auth policy", () => {
    const bypass = authPolicy({
      isControlUi: true,
      controlUiConfig: { dangerouslyDisableDeviceAuth: true },
      deviceRaw: deviceRaw("dev-1"),
    });
    expect(bypass.allowBypass).toBe(true);
    expect(bypass.device).toBeNull();

    const regular = authPolicy({
      isControlUi: false,
      controlUiConfig: { dangerouslyDisableDeviceAuth: true },
      deviceRaw: deviceRaw("dev-2"),
    });
    expect(regular.allowBypass).toBe(false);
    expect(regular.device?.id).toBe("dev-2");
  });

  test("evaluates missing-device decisions", () => {
    const policy = authPolicy();
    const controlUiStrict = authPolicy({
      isControlUi: true,
      controlUiConfig: { allowInsecureAuth: true, dangerouslyDisableDeviceAuth: false },
    });
    const controlUiNoInsecure = authPolicy({
      isControlUi: true,
      controlUiConfig: { dangerouslyDisableDeviceAuth: false },
    });
    const bypass = authPolicy({
      isControlUi: true,
      controlUiConfig: { dangerouslyDisableDeviceAuth: true },
    });

    expectMissingDeviceDecision(
      {
        hasDeviceIdentity: true,
        role: "node",
        controlUiAuthPolicy: policy,
      },
      "allow",
    );

    // Remote Control UI with allowInsecureAuth -> still rejected.
    expectMissingDeviceDecision(
      {
        role: "operator",
        isControlUi: true,
        controlUiAuthPolicy: controlUiStrict,
        isLocalClient: false,
      },
      "reject-control-ui-insecure-auth",
    );

    // Local Control UI with allowInsecureAuth -> allowed.
    expectMissingDeviceDecision(
      {
        role: "operator",
        isControlUi: true,
        controlUiAuthPolicy: controlUiStrict,
        isLocalClient: true,
      },
      "allow",
    );

    // Control UI without allowInsecureAuth, even on localhost -> rejected.
    expectMissingDeviceDecision(
      {
        role: "operator",
        isControlUi: true,
        controlUiAuthPolicy: controlUiNoInsecure,
        isLocalClient: true,
      },
      "reject-control-ui-insecure-auth",
    );

    expectMissingDeviceDecision({ controlUiAuthPolicy: policy }, "allow");

    expectMissingDeviceDecision(
      {
        controlUiAuthPolicy: policy,
        localBackendSelfPairingOk: true,
        sharedAuthOk: false,
        hasSharedAuth: false,
        isLocalClient: true,
      },
      "allow",
    );

    expectMissingDeviceDecision(
      {
        role: "node",
        controlUiAuthPolicy: policy,
        localBackendSelfPairingOk: true,
        sharedAuthOk: false,
        hasSharedAuth: false,
        isLocalClient: true,
      },
      "reject-device-required",
    );

    expectMissingDeviceDecision(
      {
        controlUiAuthPolicy: policy,
        sharedAuthOk: false,
        authOk: false,
        hasSharedAuth: true,
      },
      "reject-unauthorized",
    );

    expectMissingDeviceDecision(
      {
        role: "node",
        controlUiAuthPolicy: policy,
      },
      "reject-device-required",
    );

    // Trusted-proxy authenticated Control UI should bypass device-identity gating.
    expectMissingDeviceDecision(
      {
        role: "operator",
        isControlUi: true,
        controlUiAuthPolicy: controlUiNoInsecure,
        trustedProxyAuthOk: true,
        sharedAuthOk: false,
        hasSharedAuth: false,
      },
      "allow",
    );

    expectMissingDeviceDecision(
      {
        role: "operator",
        isControlUi: true,
        controlUiAuthPolicy: bypass,
        sharedAuthOk: false,
        authOk: false,
        hasSharedAuth: false,
      },
      "allow",
    );

    // Regression: dangerouslyDisableDeviceAuth bypass must NOT extend to node-role
    // sessions — the break-glass flag is scoped to operator Control UI only.
    // A device-less node-role connection must still be rejected even when the flag
    // is set, to prevent the flag from being abused to admit unauthorized node
    // registrations.
    expectMissingDeviceDecision(
      {
        role: "node",
        isControlUi: true,
        controlUiAuthPolicy: bypass,
        sharedAuthOk: false,
        authOk: false,
        hasSharedAuth: false,
      },
      "reject-device-required",
    );
  });

  test("dangerouslyDisableDeviceAuth skips pairing for operator control-ui only", () => {
    const bypass = authPolicy({
      isControlUi: true,
      controlUiConfig: { dangerouslyDisableDeviceAuth: true },
    });
    const strict = authPolicy({ isControlUi: true });

    expectSkipPairing(bypass, "operator", true);
    expectSkipPairing(bypass, "node", false);
    expectSkipPairing(strict, "operator", false);
    expectSkipPairing(strict, "operator", false, { pairingComplete: true });
  });

  test("auth.mode=none skips pairing for operator control-ui only", () => {
    const controlUi = authPolicy({ isControlUi: true });
    const nonControlUi = authPolicy();

    // Control UI + operator + auth.mode=none: skip pairing (the fix for #42931)
    expectSkipPairing(controlUi, "operator", true, { authMode: "none" });
    // Control UI + node role + auth.mode=none: still require pairing
    expectSkipPairing(controlUi, "node", false, { authMode: "none" });
    // Non-Control-UI + operator + auth.mode=none: still require pairing
    // (prevents #43478 regression where ALL clients bypassed pairing)
    expectSkipPairing(nonControlUi, "operator", false, { authMode: "none" });
    // Control UI + operator + auth.mode=shared-key: no change
    expectSkipPairing(controlUi, "operator", false, { authMode: "shared-key" });
    // Control UI + operator + no authMode: no change
    expectSkipPairing(controlUi, "operator", false);
  });

  // Fix 3.2: tailscale auth with authMode=none must still require device pairing
  test("auth.mode=none does not skip pairing when authMethod is tailscale", () => {
    const controlUi = authPolicy({ isControlUi: true });

    // Control UI + operator + authMode=none + tailscale: require pairing
    expectSkipPairing(controlUi, "operator", false, {
      authMode: "none",
      authMethod: "tailscale",
    });
    // Control UI + operator + authMode=none + no authMethod: still skip
    expectSkipPairing(controlUi, "operator", true, { authMode: "none" });
    // Control UI + operator + authMode=none + authMethod=token: still skip
    expectSkipPairing(controlUi, "operator", true, {
      authMode: "none",
      authMethod: "token",
    });
  });

  test("tailscale auth skips pairing only for operator control-ui with device identity", () => {
    const device = deviceRaw("dev-1");
    const controlUiWithDevice = authPolicy({
      isControlUi: true,
      deviceRaw: device,
    });
    const controlUiWithoutDevice = authPolicy({ isControlUi: true });
    const nonControlUiWithDevice = authPolicy({
      deviceRaw: device,
    });

    expectSkipPairing(controlUiWithDevice, "operator", true, {
      authMode: "token",
      authMethod: "tailscale",
    });
    expectSkipPairing(controlUiWithoutDevice, "operator", false, {
      authMode: "token",
      authMethod: "tailscale",
    });
    expectSkipPairing(controlUiWithDevice, "node", false, {
      authMode: "token",
      authMethod: "tailscale",
    });
    expectSkipPairing(nonControlUiWithDevice, "operator", false, {
      authMode: "token",
      authMethod: "tailscale",
    });
    expectSkipPairing(controlUiWithDevice, "operator", false, {
      authMode: "token",
      authMethod: "token",
    });
  });

  test("trusted-proxy control-ui bypass only applies to operator + trusted-proxy auth", () => {
    const cases: Array<{
      role: "operator" | "node";
      authMode: string;
      authOk: boolean;
      authMethod: string | undefined;
      expected: boolean;
    }> = [
      {
        role: "operator",
        authMode: "trusted-proxy",
        authOk: true,
        authMethod: "trusted-proxy",
        expected: true,
      },
      {
        role: "node",
        authMode: "trusted-proxy",
        authOk: true,
        authMethod: "trusted-proxy",
        expected: false,
      },
      {
        role: "operator",
        authMode: "token",
        authOk: true,
        authMethod: "token",
        expected: false,
      },
      {
        role: "operator",
        authMode: "trusted-proxy",
        authOk: false,
        authMethod: "trusted-proxy",
        expected: false,
      },
    ];

    for (const tc of cases) {
      expect(
        isTrustedProxyControlUiOperatorAuth({
          isControlUi: true,
          role: tc.role,
          authMode: tc.authMode,
          authOk: tc.authOk,
          authMethod: tc.authMethod,
        }),
      ).toBe(tc.expected);
    }
  });

  test("clears unbound scopes for device-less shared auth outside explicit preservation cases", () => {
    const nonControlUi = authPolicy();
    const controlUi = authPolicy({
      isControlUi: true,
      controlUiConfig: { allowInsecureAuth: true },
    });

    expectClearsUnboundScopes({ controlUiAuthPolicy: nonControlUi }, true);
    expectClearsUnboundScopes(
      {
        controlUiAuthPolicy: nonControlUi,
        authMethod: "password",
      },
      true,
    );
    expect(
      shouldClearUnboundScopesForMissingDeviceIdentity({
        decision: { kind: "allow" },
        controlUiAuthPolicy: nonControlUi,
        preserveInsecureLocalControlUiScopes: false,
        preserveLocalBackendSharedAuthScopes: true,
        authMethod: "token",
      }),
    ).toBe(false);

    expect(
      shouldClearUnboundScopesForMissingDeviceIdentity({
        decision: { kind: "allow" },
        controlUiAuthPolicy: nonControlUi,
        preserveInsecureLocalControlUiScopes: false,
        preserveLocalBackendSharedAuthScopes: true,
        authMethod: "password",
      }),
    ).toBe(false);

    expect(
      shouldClearUnboundScopesForMissingDeviceIdentity({
        decision: { kind: "allow" },
        controlUiAuthPolicy: nonControlUi,
        preserveInsecureLocalControlUiScopes: false,
        preserveLocalBackendSharedAuthScopes: true,
        authMethod: "trusted-proxy",
      }),
    ).toBe(true);
    expectClearsUnboundScopes(
      {
        controlUiAuthPolicy: nonControlUi,
        authMethod: "trusted-proxy",
        trustedProxyAuthOk: true,
      },
      true,
    );
    expectClearsUnboundScopes(
      {
        controlUiAuthPolicy: controlUi,
        preserveInsecureLocalControlUiScopes: true,
      },
      false,
    );
    expectClearsUnboundScopes(
      {
        decision: { kind: "reject-device-required" },
        controlUiAuthPolicy: nonControlUi,
        authMethod: undefined,
      },
      true,
    );
  });

  // CWE-290 contract: a TUI client must not be able to use any path gated
  // by isControlUi, even when the operator has configured the
  // dangerouslyDisableDeviceAuth break-glass, allowInsecureAuth for
  // localhost, trusted-proxy auth, tailscale, or authMode=none. Only the
  // browser Control UI may take those bypasses. message-handler.ts:698
  // must use isBrowserOperatorUiClient so the boolean is strict.
  describe("TUI client cannot trigger Control-UI bypass (CWE-290)", () => {
    const tuiClient = { id: "openclaw-tui", mode: "ui" as const };
    const controlUiClient = { id: "openclaw-control-ui", mode: "ui" as const };

    const tuiIsControlUi = isBrowserOperatorUiClient(tuiClient);
    const controlUiIsControlUi = isBrowserOperatorUiClient(controlUiClient);

    test("isBrowserOperatorUiClient distinguishes TUI from CONTROL_UI", () => {
      expect(tuiIsControlUi).toBe(false);
      expect(controlUiIsControlUi).toBe(true);
    });

    test("dangerouslyDisableDeviceAuth break-glass: TUI is rejected, CONTROL_UI allowed", () => {
      const bypass = resolveControlUiAuthPolicy({
        isControlUi: tuiIsControlUi,
        controlUiConfig: { dangerouslyDisableDeviceAuth: true },
        deviceRaw: deviceRaw("dev-1"),
      });
      expect(bypass.allowBypass).toBe(false);
      expect(bypass.device?.id).toBe("dev-1");

      const controlUiBypass = resolveControlUiAuthPolicy({
        isControlUi: controlUiIsControlUi,
        controlUiConfig: { dangerouslyDisableDeviceAuth: true },
        deviceRaw: deviceRaw("dev-2"),
      });
      expect(controlUiBypass.allowBypass).toBe(true);
      expect(controlUiBypass.device).toBeNull();

      // TUI: sharedAuthOk=false, hasSharedAuth=false, isLocalClient=true.
      // The bypass (path 3) does not fire (isControlUi=false); the
      // roleCanSkipDeviceIdentity fallthrough (path 6) does not fire
      // (sharedAuthOk=false). The only path is reject-device-required.
      expect(
        evaluateMissingDeviceIdentity({
          hasDeviceIdentity: false,
          role: "operator",
          isControlUi: tuiIsControlUi,
          controlUiAuthPolicy: bypass,
          sharedAuthOk: false,
          authOk: false,
          hasSharedAuth: false,
          isLocalClient: true,
        }),
      ).toEqual({ kind: "reject-device-required" });

      // CONTROL_UI: bypass fires at path 3.
      expect(
        evaluateMissingDeviceIdentity({
          hasDeviceIdentity: false,
          role: "operator",
          isControlUi: controlUiIsControlUi,
          controlUiAuthPolicy: controlUiBypass,
          sharedAuthOk: false,
          authOk: false,
          hasSharedAuth: false,
          isLocalClient: true,
        }),
      ).toEqual({ kind: "allow" });
    });

    test("allowInsecureAuth is a no-op for TUI: same result with or without the flag", () => {
      // allowInsecureAuth grants browser Control UI a path around the
      // reject-control-ui-insecure-auth reject when on localhost. It is a
      // Control-UI-specific shortcut: with isControlUi=false the flag
      // must not influence the decision. TUI's result must match across
      // (allowInsecureAuth true vs. undefined) for any other fixed input.
      const tuiOff = resolveControlUiAuthPolicy({
        isControlUi: tuiIsControlUi,
        controlUiConfig: {},
        deviceRaw: null,
      });
      const tuiOn = resolveControlUiAuthPolicy({
        isControlUi: tuiIsControlUi,
        controlUiConfig: { allowInsecureAuth: true },
        deviceRaw: null,
      });

      // TUI with shared auth, on localhost — allow via shared-auth
      // fallthrough. Both configs must produce the same kind.
      for (const policy of [tuiOff, tuiOn]) {
        expect(
          evaluateMissingDeviceIdentity({
            hasDeviceIdentity: false,
            role: "operator",
            isControlUi: tuiIsControlUi,
            controlUiAuthPolicy: policy,
            sharedAuthOk: true,
            authOk: true,
            hasSharedAuth: true,
            isLocalClient: true,
          }).kind,
        ).toBe("allow");
      }

      // TUI without shared auth, on localhost — reject-device-required.
      // Both configs must produce the same kind.
      for (const policy of [tuiOff, tuiOn]) {
        expect(
          evaluateMissingDeviceIdentity({
            hasDeviceIdentity: false,
            role: "operator",
            isControlUi: tuiIsControlUi,
            controlUiAuthPolicy: policy,
            sharedAuthOk: false,
            authOk: false,
            hasSharedAuth: false,
            isLocalClient: true,
          }).kind,
        ).toBe("reject-device-required");
      }
    });

    test("trusted-proxy auth bypass: TUI is rejected, CONTROL_UI allowed", () => {
      expect(
        isTrustedProxyControlUiOperatorAuth({
          isControlUi: tuiIsControlUi,
          role: "operator",
          authMode: "trusted-proxy",
          authOk: true,
          authMethod: "trusted-proxy",
        }),
      ).toBe(false);

      expect(
        isTrustedProxyControlUiOperatorAuth({
          isControlUi: controlUiIsControlUi,
          role: "operator",
          authMode: "trusted-proxy",
          authOk: true,
          authMethod: "trusted-proxy",
        }),
      ).toBe(true);

      const controlUiPolicy = resolveControlUiAuthPolicy({
        isControlUi: controlUiIsControlUi,
        controlUiConfig: {},
        deviceRaw: null,
      });
      expect(
        evaluateMissingDeviceIdentity({
          hasDeviceIdentity: false,
          role: "operator",
          isControlUi: controlUiIsControlUi,
          controlUiAuthPolicy: controlUiPolicy,
          trustedProxyAuthOk: true,
          sharedAuthOk: false,
          authOk: false,
          hasSharedAuth: false,
          isLocalClient: false,
        }).kind,
      ).toBe("allow");

      const tuiPolicy = resolveControlUiAuthPolicy({
        isControlUi: tuiIsControlUi,
        controlUiConfig: {},
        deviceRaw: null,
      });
      expect(
        evaluateMissingDeviceIdentity({
          hasDeviceIdentity: false,
          role: "operator",
          isControlUi: tuiIsControlUi,
          controlUiAuthPolicy: tuiPolicy,
          trustedProxyAuthOk: true,
          sharedAuthOk: false,
          authOk: false,
          hasSharedAuth: false,
          isLocalClient: false,
        }).kind,
      ).toBe("reject-device-required");
    });

    test("authMode=none pairing skip: TUI must pair, CONTROL_UI skips", () => {
      const tuiPolicy = resolveControlUiAuthPolicy({
        isControlUi: tuiIsControlUi,
        controlUiConfig: {},
        deviceRaw: null,
      });
      const controlUiPolicy = resolveControlUiAuthPolicy({
        isControlUi: controlUiIsControlUi,
        controlUiConfig: {},
        deviceRaw: null,
      });

      expect(shouldSkipControlUiPairing(tuiPolicy, "operator", false, "none")).toBe(false);
      expect(shouldSkipControlUiPairing(controlUiPolicy, "operator", false, "none")).toBe(true);
    });

    test("tailscale+operator+device pairing skip: TUI must pair, CONTROL_UI skips", () => {
      const device = deviceRaw("dev-1");
      const tuiPolicy = resolveControlUiAuthPolicy({
        isControlUi: tuiIsControlUi,
        controlUiConfig: {},
        deviceRaw: device,
      });
      const controlUiPolicy = resolveControlUiAuthPolicy({
        isControlUi: controlUiIsControlUi,
        controlUiConfig: {},
        deviceRaw: device,
      });

      expect(shouldSkipControlUiPairing(tuiPolicy, "operator", false, "token", "tailscale")).toBe(
        false,
      );
      expect(
        shouldSkipControlUiPairing(controlUiPolicy, "operator", false, "token", "tailscale"),
      ).toBe(true);
    });
  });
});
