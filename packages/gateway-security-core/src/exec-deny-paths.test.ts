import { describe, expect, it } from "vitest";
import {
  type ExecDenyPathsConfig,
  checkExecDenyPath,
  extractPathsFromCommand,
} from "./exec-deny-paths.js";

// ---------------------------------------------------------------------------
// checkExecDenyPath
// ---------------------------------------------------------------------------

describe("checkExecDenyPath", () => {
  describe("default deny patterns", () => {
    it("denies reading from ~/.openclaw/secrets/", () => {
      expect(checkExecDenyPath("cat ~/.openclaw/secrets/telegram.env")).toBeDefined();
    });

    it("denies reading from ~/.openclaw/credentials/", () => {
      expect(checkExecDenyPath("cat ~/.openclaw/credentials/aws-creds")).toBeDefined();
    });

    it("denies reading .env", () => {
      expect(checkExecDenyPath("head .env")).toBeDefined();
    });

    it("denies reading .env.production", () => {
      expect(checkExecDenyPath("cat .env.production")).toBeDefined();
    });

    it("denies reading files with -secret in the name", () => {
      expect(checkExecDenyPath("cat /opt/my-secret-key")).toBeDefined();
    });

    it("denies reading files with credential in the name", () => {
      expect(checkExecDenyPath("cat /etc/credential-store")).toBeDefined();
    });

    it("denies reading token .env files", () => {
      expect(checkExecDenyPath("cat app-token.env")).toBeDefined();
    });

    it("denies reading SSH private keys", () => {
      expect(checkExecDenyPath("cat ~/.ssh/id_rsa")).toBeDefined();
    });

    it("denies reading GPG directory", () => {
      expect(checkExecDenyPath("cat ~/.gnupg/private-keys-v1.d/abc.key")).toBeDefined();
    });

    it("allows reading /etc/hosts", () => {
      expect(checkExecDenyPath("cat /etc/hosts")).toBeUndefined();
    });

    it("allows reading regular files", () => {
      expect(checkExecDenyPath("cat myfile.txt")).toBeUndefined();
    });

    it("allows reading non-sensitive paths", () => {
      expect(checkExecDenyPath("head /var/log/syslog")).toBeUndefined();
    });

    it("allows echo commands without paths", () => {
      expect(checkExecDenyPath("echo hello world")).toBeUndefined();
    });
  });

  describe("custom deny patterns", () => {
    const config: ExecDenyPathsConfig = {
      denyPathPatterns: ["**/forbidden/**", "**/*.key"],
    };

    it("matches custom patterns", () => {
      expect(checkExecDenyPath("cat /opt/forbidden/data", config)).toBeDefined();
    });

    it("matches custom extension patterns", () => {
      expect(checkExecDenyPath("cat server.key", config)).toBeDefined();
    });

    it("does not match default patterns when custom config is provided", () => {
      // With custom config, defaults are overridden entirely
      expect(checkExecDenyPath("cat .env", config)).toBeUndefined();
    });

    it("matches nested custom patterns", () => {
      expect(checkExecDenyPath("cat /deep/nested/forbidden/file.txt", config)).toBeDefined();
    });
  });

  describe("empty patterns array disables checks", () => {
    const disabledConfig: ExecDenyPathsConfig = {
      denyPathPatterns: [],
    };

    it("allows sensitive paths when patterns are empty", () => {
      expect(
        checkExecDenyPath("cat ~/.openclaw/secrets/telegram.env", disabledConfig),
      ).toBeUndefined();
    });

    it("allows .env when patterns are empty", () => {
      expect(checkExecDenyPath("head .env", disabledConfig)).toBeUndefined();
    });
  });

  describe("undefined config uses defaults", () => {
    it("uses default patterns when config is undefined", () => {
      expect(checkExecDenyPath("cat ~/.openclaw/secrets/api.env", undefined)).toBeDefined();
    });
  });

  describe("multiple paths in one command", () => {
    it("denies when any path in a cp command matches", () => {
      // cp secrets.env backup.env — secrets.env matches *-secret* pattern
      expect(checkExecDenyPath("cp secrets.env backup.env")).toBeDefined();
    });

    it("denies when the second path matches but the first doesn't", () => {
      expect(checkExecDenyPath("cp normal.txt ~/.openclaw/secrets/")).toBeDefined();
    });

    it("allows when neither path matches", () => {
      expect(checkExecDenyPath("cp file1.txt file2.txt")).toBeUndefined();
    });
  });

  describe("quoted paths", () => {
    it("denies quoted sensitive paths", () => {
      expect(checkExecDenyPath('cat "~/.openclaw/secrets/telegram.env"')).toBeDefined();
    });

    it("denies single-quoted sensitive paths", () => {
      expect(checkExecDenyPath("cat '.env'")).toBeDefined();
    });
  });

  describe("redirect targets", () => {
    it("denies redirect output to sensitive paths", () => {
      expect(checkExecDenyPath("echo hello > .env")).toBeDefined();
    });

    it("denies redirect input from sensitive paths", () => {
      expect(checkExecDenyPath("sort < .env.production")).toBeDefined();
    });
  });
});

// ---------------------------------------------------------------------------
// extractPathsFromCommand
// ---------------------------------------------------------------------------

describe("extractPathsFromCommand", () => {
  it("extracts path from cat command", () => {
    expect(extractPathsFromCommand("cat /etc/hosts")).toEqual(["/etc/hosts"]);
  });

  it("extracts path from head command", () => {
    expect(extractPathsFromCommand("head -5 /var/log/syslog")).toEqual(["/var/log/syslog"]);
  });

  it("extracts path from less command", () => {
    expect(extractPathsFromCommand("less README.md")).toEqual(["README.md"]);
  });

  it("extracts paths from cp command", () => {
    expect(extractPathsFromCommand("cp file1.txt file2.txt")).toEqual(["file1.txt", "file2.txt"]);
  });

  it("extracts paths from mv command", () => {
    expect(extractPathsFromCommand("mv old.txt new.txt")).toEqual(["old.txt", "new.txt"]);
  });

  it("extracts paths from rm command", () => {
    expect(extractPathsFromCommand("rm -rf /tmp/build")).toEqual(["/tmp/build"]);
  });

  it("skips flags", () => {
    const paths = extractPathsFromCommand("cat -n -A myfile.txt");
    expect(paths).toContain("myfile.txt");
    expect(paths).not.toContain("-n");
    expect(paths).not.toContain("-A");
  });

  it("extracts tilde-expanded paths", () => {
    const paths = extractPathsFromCommand("cat ~/myfile.txt");
    expect(paths).toContain("~/myfile.txt");
  });

  it("extracts redirect targets", () => {
    const paths = extractPathsFromCommand("echo hello > output.txt");
    expect(paths).toContain("output.txt");
  });

  it("extracts append redirect targets", () => {
    const paths = extractPathsFromCommand("echo hello >> output.txt");
    expect(paths).toContain("output.txt");
  });

  it("extracts input redirect targets", () => {
    const paths = extractPathsFromCommand("sort < input.txt");
    expect(paths).toContain("input.txt");
  });

  it("extracts combined redirect targets like >file", () => {
    const paths = extractPathsFromCommand("echo hello >output.txt");
    expect(paths).toContain("output.txt");
  });

  it("extracts multiple paths from multi-arg commands", () => {
    const paths = extractPathsFromCommand("cp secrets.env backup.env");
    expect(paths).toEqual(["secrets.env", "backup.env"]);
  });

  it("extracts path from vim", () => {
    expect(extractPathsFromCommand("vim ~/.ssh/config")).toEqual(["~/.ssh/config"]);
  });

  it("extracts path from nano", () => {
    expect(extractPathsFromCommand("nano /etc/fstab")).toEqual(["/etc/fstab"]);
  });

  it("handles -- end-of-flags sentinel", () => {
    const paths = extractPathsFromCommand("cat -- -myfile.txt");
    expect(paths).toContain("-myfile.txt");
  });

  it("extracts paths from piped commands (only the relevant side)", () => {
    const paths = extractPathsFromCommand("cat .env | grep KEY");
    // cat .env → .env is a positional arg of cat; grep KEY → KEY is a search term, not a path
    expect(paths).toContain(".env");
  });

  it("extracts paths from commands with absolute paths", () => {
    const paths = extractPathsFromCommand("/usr/bin/cat /etc/hosts");
    expect(paths).toEqual(["/etc/hosts"]);
  });

  it("returns empty for commands with no paths", () => {
    expect(extractPathsFromCommand("echo hello world")).toEqual([]);
  });

  it("extracts paths from commands with --option=value syntax", () => {
    const paths = extractPathsFromCommand("cat --output=myfile.txt");
    // --output=myfile.txt → after stripFlag, candidate is "myfile.txt"
    expect(paths).toContain("myfile.txt");
  });

  it("extracts path from open command", () => {
    expect(extractPathsFromCommand("open ~/Desktop/file.pdf")).toEqual(["~/Desktop/file.pdf"]);
  });

  it("extracts path from tail command with flags", () => {
    const paths = extractPathsFromCommand("tail -n 10 /var/log/syslog");
    expect(paths).toEqual(["/var/log/syslog"]);
  });
});
