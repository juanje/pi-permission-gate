import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  DEFAULT_POLICY,
  evaluateToolCall,
  expandPattern,
  extractInput,
  globToRegex,
  initLog,
  isSelfProtected,
  isToolAllowedAtSessionLevel,
  loadJsonFile,
  loadPolicy,
  logDecision,
  MAX_LOG_INPUT_LENGTH,
  matchGlob,
  mergePolicies,
  mergeToolRules,
  normalizePath,
  type Policy,
} from "../extensions/permission-gate.js";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("globToRegex", () => {
  it("matches exact string, not prefix", () => {
    const regex = globToRegex("date");
    expect(regex.test("date")).toBe(true);
    expect(regex.test("date-util")).toBe(false);
  });

  it("matches wildcard prefix patterns", () => {
    const regex = globToRegex("bin/*");
    expect(regex.test("bin/gitlab-query upstream /pipelines")).toBe(true);
  });

  it("matches env file patterns", () => {
    const regex = globToRegex("*.env*");
    expect(regex.test("cat .env")).toBe(true);
    expect(regex.test("head .env.bak")).toBe(true);
    expect(regex.test("grep x .env")).toBe(true);
  });

  it("requires trailing space for date * pattern", () => {
    const regex = globToRegex("date *");
    expect(regex.test("date +%Y")).toBe(true);
    expect(regex.test("date")).toBe(false);
  });

  it("matches single character with ?", () => {
    const regex = globToRegex("?");
    expect(regex.test("a")).toBe(true);
    expect(regex.test("ab")).toBe(false);
  });

  it("matches multiline strings with *", () => {
    const regex = globToRegex("git commit *");
    expect(regex.test('git commit -m "single line"')).toBe(true);
    expect(regex.test('git commit -m "line1\nline2\nline3"')).toBe(true);
    expect(regex.test("git commit -m \"$(cat <<'EOF'\nfeat: add feature\n\nDetails here\nEOF\n)\"")).toBe(true);
  });
});

describe("matchGlob", () => {
  it("returns false for empty value", () => {
    expect(matchGlob("bin/*", "")).toBe(false);
  });

  it("matches exact command", () => {
    expect(matchGlob("date", "date")).toBe(true);
  });

  it("matches wildcard commands", () => {
    expect(matchGlob("bin/*", "bin/fetch-test-log --full url")).toBe(true);
  });

  it("matches basename fallback", () => {
    expect(matchGlob(".env*", "path/to/.env")).toBe(true);
  });

  it("expands tilde in patterns", () => {
    const sshConfig = join(homedir(), ".ssh/config");
    expect(matchGlob("~/.ssh/*", sshConfig)).toBe(true);
  });

  it("checks original pattern after expansion", () => {
    expect(matchGlob("~/.ssh/*", "~/.ssh/id_rsa")).toBe(true);
  });

  it("returns false when no pattern matches", () => {
    expect(matchGlob("bin/*", "cat foo")).toBe(false);
  });

  it("matches env deny catch-all patterns", () => {
    expect(matchGlob("*.env*", "cat .env")).toBe(true);
    expect(matchGlob("*.env*", "head .env.example")).toBe(true);
  });
});

describe("expandPattern", () => {
  it("expands home-relative patterns", () => {
    expect(expandPattern("~/.ssh/*")).toBe(join(homedir(), ".ssh/*"));
  });

  it("leaves non-tilde patterns unchanged", () => {
    expect(expandPattern("bin/*")).toBe("bin/*");
  });
});

describe("normalizePath", () => {
  const cwd = "/project/root";

  it("returns empty string unchanged", () => {
    expect(normalizePath("", cwd)).toBe("");
  });

  it("normalizes relative segments", () => {
    expect(normalizePath("./tools/../.env", cwd)).toBe(".env");
  });

  it("expands home paths outside project as absolute", () => {
    const result = normalizePath("~/notes.txt", cwd);
    expect(result).toBe(join(homedir(), "notes.txt"));
  });

  it("relativizes absolute paths inside project", () => {
    expect(normalizePath("/project/root/kb/foo.md", cwd)).toBe("kb/foo.md");
  });

  it("keeps absolute paths outside project", () => {
    expect(normalizePath("/other/path", cwd)).toBe("/other/path");
  });

  it("leaves simple relative paths unchanged", () => {
    expect(normalizePath("kb/active/foo.md", cwd)).toBe("kb/active/foo.md");
  });
});

describe("extractInput", () => {
  const cwd = "/project/root";

  it("returns bash command", () => {
    expect(extractInput("bash", { command: "date" }, cwd)).toBe("date");
  });

  it("returns normalized path for read/write/edit", () => {
    expect(extractInput("read", { path: "kb/foo.md" }, cwd)).toBe("kb/foo.md");
    expect(extractInput("write", { path: "./kb/foo.md" }, cwd)).toBe("kb/foo.md");
    expect(extractInput("edit", { path: "kb/foo.md" }, cwd)).toBe("kb/foo.md");
  });

  it("returns grep pattern", () => {
    expect(extractInput("grep", { pattern: "error" }, cwd)).toBe("error");
  });

  it("returns find glob", () => {
    expect(extractInput("find", { glob: "*.ts" }, cwd)).toBe("*.ts");
  });

  it("returns empty string for unknown tools", () => {
    expect(extractInput("unknown", { foo: "bar" }, cwd)).toBe("");
  });

  it("returns empty string for missing fields", () => {
    expect(extractInput("bash", {}, cwd)).toBe("");
    expect(extractInput("read", {}, cwd)).toBe("");
  });
});

describe("isSelfProtected", () => {
  it("protects permissions.json", () => {
    expect(isSelfProtected(".pi/permissions.json")).toBe(true);
  });

  it("protects permissions.local.json", () => {
    expect(isSelfProtected(".pi/permissions.local.json")).toBe(true);
  });

  it("protects extension files", () => {
    expect(isSelfProtected(".pi/extensions/foo.ts")).toBe(true);
  });

  it("protects bash commands referencing protected paths", () => {
    expect(isSelfProtected("cat .pi/permissions.json")).toBe(true);
  });

  it("allows unrelated paths", () => {
    expect(isSelfProtected("kb/foo.md")).toBe(false);
  });
});

describe("isToolAllowedAtSessionLevel", () => {
  it("denies simple deny rule", () => {
    const policy: Policy = {
      defaultMode: "allow",
      permissions: { tools: { grep: "deny" } },
    };
    expect(isToolAllowedAtSessionLevel("grep", policy)).toBe(false);
  });

  it("allows simple allow rule", () => {
    const policy: Policy = {
      defaultMode: "deny",
      permissions: { tools: { read: "allow" } },
    };
    expect(isToolAllowedAtSessionLevel("read", policy)).toBe(true);
  });

  it("allows object rules for session filtering", () => {
    const policy: Policy = {
      defaultMode: "deny",
      permissions: {
        tools: { bash: { allow: ["date"], default: "deny" } },
      },
    };
    expect(isToolAllowedAtSessionLevel("bash", policy)).toBe(true);
  });

  it("uses defaultMode deny for undefined tools", () => {
    const policy: Policy = { defaultMode: "deny", permissions: { tools: {} } };
    expect(isToolAllowedAtSessionLevel("write", policy)).toBe(false);
  });

  it("uses defaultMode allow for undefined tools", () => {
    const policy: Policy = { defaultMode: "allow", permissions: { tools: {} } };
    expect(isToolAllowedAtSessionLevel("write", policy)).toBe(true);
  });
});

describe("mergeToolRules", () => {
  it("local string overrides base object", () => {
    expect(mergeToolRules({ allow: ["a"] }, "deny")).toBe("deny");
  });

  it("local string overrides base string", () => {
    expect(mergeToolRules("allow", "deny")).toBe("deny");
  });

  it("merges deny arrays", () => {
    const merged = mergeToolRules({ deny: ["a"] }, { deny: ["b"] }) as { deny?: string[] };
    expect(merged.deny).toEqual(["a", "b"]);
  });

  it("merges allow arrays", () => {
    const merged = mergeToolRules({ allow: ["a"] }, { allow: ["b"] }) as { allow?: string[] };
    expect(merged.allow).toEqual(["a", "b"]);
  });

  it("merges path rules", () => {
    const merged = mergeToolRules(
      { paths: { deny: ["a"], allow: ["x"] } },
      { paths: { deny: ["b"], allow: ["y"] } },
    ) as { paths?: { deny?: string[]; allow?: string[] } };
    expect(merged.paths?.deny).toEqual(["a", "b"]);
    expect(merged.paths?.allow).toEqual(["x", "y"]);
  });
});

describe("mergePolicies", () => {
  it("returns default when both are null", () => {
    expect(mergePolicies(null, null)).toEqual(DEFAULT_POLICY);
  });

  it("returns base when local is null", () => {
    const base: Policy = { defaultMode: "allow", permissions: { tools: {} } };
    expect(mergePolicies(base, null)).toEqual(base);
  });

  it("returns local when base is null", () => {
    const local: Policy = { defaultMode: "deny", permissions: { tools: { read: "allow" } } };
    expect(mergePolicies(null, local)).toEqual(local);
  });

  it("local defaultMode wins", () => {
    const base: Policy = { defaultMode: "allow", permissions: { tools: {} } };
    const local: Policy = { defaultMode: "deny", permissions: { tools: {} } };
    expect(mergePolicies(base, local).defaultMode).toBe("deny");
  });

  it("deep merges tool rules", () => {
    const base: Policy = {
      defaultMode: "deny",
      permissions: { tools: { bash: { allow: ["date"] } } },
    };
    const local: Policy = {
      defaultMode: "deny",
      permissions: { tools: { bash: { deny: ["rm *"] } } },
    };
    const merged = mergePolicies(base, local);
    expect(merged.permissions.tools.bash).toEqual({
      allow: ["date"],
      deny: ["rm *"],
    });
  });
});

describe("loadJsonFile and loadPolicy", () => {
  it("returns null for missing file", () => {
    const dir = makeTempDir("pg-missing-");
    expect(loadJsonFile(join(dir, "missing.json"))).toBeNull();
  });

  it("parses valid JSON", () => {
    const dir = makeTempDir("pg-valid-");
    const file = join(dir, "permissions.json");
    const policy: Policy = { defaultMode: "deny", permissions: { tools: { read: "allow" } } };
    writeFileSync(file, JSON.stringify(policy));
    expect(loadJsonFile(file)).toEqual(policy);
  });

  it("returns null for invalid JSON", () => {
    const dir = makeTempDir("pg-invalid-");
    const file = join(dir, "permissions.json");
    writeFileSync(file, "{not-json");
    expect(loadJsonFile(file)).toBeNull();
  });

  it("merges base and local policy files", () => {
    const dir = makeTempDir("pg-load-");
    mkdirSync(join(dir, ".pi"), { recursive: true });

    writeFileSync(
      join(dir, ".pi", "permissions.json"),
      JSON.stringify({
        defaultMode: "deny",
        permissions: { tools: { bash: { allow: ["date"] } } },
      }),
    );
    writeFileSync(
      join(dir, ".pi", "permissions.local.json"),
      JSON.stringify({
        defaultMode: "deny",
        permissions: { tools: { bash: { deny: ["rm *"] } } },
      }),
    );

    const policy = loadPolicy(dir);
    expect(policy.permissions.tools.bash).toEqual({
      allow: ["date"],
      deny: ["rm *"],
    });
  });
});

describe("evaluateToolCall", () => {
  const cwd = "/project";

  it("blocks simple deny rule", () => {
    const policy: Policy = {
      defaultMode: "allow",
      permissions: { tools: { grep: "deny" } },
    };
    const result = evaluateToolCall("grep", { pattern: "x" }, policy, cwd);
    expect(result).toEqual({ block: true, reason: "Tool 'grep' is denied" });
  });

  it("allows simple allow rule", () => {
    const policy: Policy = {
      defaultMode: "deny",
      permissions: { tools: { read: "allow" } },
    };
    expect(evaluateToolCall("read", { path: "kb/foo.md" }, policy, cwd)).toBeUndefined();
  });

  it("blocks undefined tool with deny defaultMode", () => {
    const policy: Policy = { defaultMode: "deny", permissions: { tools: {} } };
    const result = evaluateToolCall("write", { path: "x" }, policy, cwd);
    expect(result).toEqual({ block: true, reason: "Tool 'write' not in allowlist" });
  });

  it("allows undefined tool with allow defaultMode", () => {
    const policy: Policy = { defaultMode: "allow", permissions: { tools: {} } };
    expect(evaluateToolCall("write", { path: "x" }, policy, cwd)).toBeUndefined();
  });

  it("blocks command matching deny pattern", () => {
    const policy: Policy = {
      defaultMode: "deny",
      permissions: {
        tools: { bash: { deny: ["rm *"], allow: ["date"], default: "deny" } },
      },
    };
    const result = evaluateToolCall("bash", { command: "rm -rf /" }, policy, cwd);
    expect(result?.block).toBe(true);
  });

  it("allows command matching allow pattern", () => {
    const policy: Policy = {
      defaultMode: "deny",
      permissions: {
        tools: { bash: { allow: ["date"], default: "deny" } },
      },
    };
    expect(evaluateToolCall("bash", { command: "date" }, policy, cwd)).toBeUndefined();
  });

  it("blocks path matching paths.deny", () => {
    const policy: Policy = {
      defaultMode: "deny",
      permissions: {
        tools: {
          read: {
            paths: { deny: ["*.env*"] },
            default: "allow",
          },
        },
      },
    };
    const result = evaluateToolCall("read", { path: ".env" }, policy, cwd);
    expect(result?.block).toBe(true);
  });

  it("allows path matching paths.allow", () => {
    const policy: Policy = {
      defaultMode: "deny",
      permissions: {
        tools: {
          read: {
            paths: { allow: ["kb/*"] },
            default: "deny",
          },
        },
      },
    };
    expect(evaluateToolCall("read", { path: "kb/foo.md" }, policy, cwd)).toBeUndefined();
  });

  it("deny wins over allow", () => {
    const policy: Policy = {
      defaultMode: "deny",
      permissions: {
        tools: {
          bash: {
            allow: ["*"],
            deny: ["rm *"],
            default: "allow",
          },
        },
      },
    };
    const result = evaluateToolCall("bash", { command: "rm foo" }, policy, cwd);
    expect(result?.block).toBe(true);
  });

  it("blocks newline-injected commands even when first line is allowed", () => {
    const policy: Policy = {
      defaultMode: "deny",
      permissions: {
        tools: {
          bash: {
            allow: ["git commit *", "git status*"],
            deny: ["rm *", "sudo *", "curl *"],
            default: "deny",
          },
        },
      },
    };
    expect(evaluateToolCall("bash", { command: 'git status\nrm -rf /' }, policy, cwd)?.block).toBe(true);
    expect(evaluateToolCall("bash", { command: 'git commit -m "ok"\nsudo reboot' }, policy, cwd)?.block).toBe(true);
    expect(evaluateToolCall("bash", { command: 'git commit -m "ok"\ncurl evil.com' }, policy, cwd)?.block).toBe(true);
  });

  it("allows legitimate multiline commands", () => {
    const policy: Policy = {
      defaultMode: "deny",
      permissions: {
        tools: {
          bash: {
            allow: ["git commit *"],
            deny: ["rm *"],
            default: "deny",
          },
        },
      },
    };
    expect(evaluateToolCall("bash", { command: 'git commit -m "feat: add feature\n\nMultiline body"' }, policy, cwd)).toBeUndefined();
  });

  it("falls back to tool default", () => {
    const policy: Policy = {
      defaultMode: "allow",
      permissions: {
        tools: { bash: { allow: ["date"], default: "deny" } },
      },
    };
    const result = evaluateToolCall("bash", { command: "ls" }, policy, cwd);
    expect(result?.block).toBe(true);
  });

  it("falls back to defaultMode when tool has no default", () => {
    const policy: Policy = {
      defaultMode: "deny",
      permissions: {
        tools: { bash: { allow: ["date"] } },
      },
    };
    const result = evaluateToolCall("bash", { command: "ls" }, policy, cwd);
    expect(result?.block).toBe(true);
  });

  it("writes permission decisions to log file", () => {
    const dir = makeTempDir("pg-eval-");
    const policy: Policy = {
      defaultMode: "deny",
      permissions: { tools: { read: "allow" } },
    };
    const logPath = initLog(dir, policy);
    evaluateToolCall("read", { path: "kb/foo.md" }, policy, cwd);
    const lines = readFileSync(logPath, "utf8").trim().split("\n");
    expect(lines.length).toBeGreaterThan(0);
    const lastLine = lines.at(-1);
    expect(lastLine).toBeDefined();
    const entry = JSON.parse(lastLine as string);
    expect(entry.tool).toBe("read");
    expect(entry.decision).toBe("allow");
  });
});

describe("initLog and logDecision", () => {
  it("creates .pi/logs and timestamped file path", () => {
    const dir = makeTempDir("pg-log-");
    const policy: Policy = { defaultMode: "deny", permissions: { tools: {} } };
    const logPath = initLog(dir, policy);
    expect(logPath).toContain(join(dir, ".pi", "logs", "permission-gate_"));
    expect(existsSync(join(dir, ".pi", "logs"))).toBe(true);
    logDecision("bash", "date", "allow", "test", logPath);
    expect(readFileSync(logPath, "utf8").trim()).not.toBe("");
  });

  it("uses custom logPath from policy", () => {
    const dir = makeTempDir("pg-log-custom-");
    const policy: Policy = {
      defaultMode: "deny",
      logPath: "custom-logs",
      permissions: { tools: {} },
    };
    const logPath = initLog(dir, policy);
    expect(logPath.startsWith(join(dir, "custom-logs", "permission-gate_"))).toBe(true);
  });

  it("truncates logged input to 200 characters", () => {
    const dir = makeTempDir("pg-log-trunc-");
    const logPath = join(dir, "test.jsonl");
    const longInput = "x".repeat(MAX_LOG_INPUT_LENGTH + 100);
    logDecision("bash", longInput, "allow", "test", logPath);
    const entry = JSON.parse(readFileSync(logPath, "utf8").trim());
    expect(entry.input).toHaveLength(MAX_LOG_INPUT_LENGTH);
  });
});

describe("secret redaction in logs", () => {
  it("redacts Anthropic API keys", () => {
    const dir = makeTempDir("pg-redact-");
    const logPath = join(dir, "test.jsonl");
    logDecision(
      "bash",
      "curl -H 'x-api-key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijk'",
      "allow",
      "test",
      logPath,
    );
    const entry = JSON.parse(readFileSync(logPath, "utf8").trim());
    expect(entry.input).not.toContain("sk-ant-api03-");
    expect(entry.input).toContain("[REDACTED");
  });

  it("redacts GitHub PATs", () => {
    const dir = makeTempDir("pg-redact-gh-");
    const logPath = join(dir, "test.jsonl");
    logDecision(
      "bash",
      "git clone https://ghp_1234567890abcdefghijklmnopqrstuvwxyz@github.com/repo",
      "allow",
      "test",
      logPath,
    );
    const entry = JSON.parse(readFileSync(logPath, "utf8").trim());
    expect(entry.input).not.toContain("ghp_1234567890");
    expect(entry.input).toContain("[REDACTED");
  });

  it("redacts GitLab PATs", () => {
    const dir = makeTempDir("pg-redact-gl-");
    const logPath = join(dir, "test.jsonl");
    logDecision("bash", "export GITLAB_TOKEN=glpat-abcdefghij1234567890", "allow", "test", logPath);
    const entry = JSON.parse(readFileSync(logPath, "utf8").trim());
    expect(entry.input).not.toContain("glpat-");
    expect(entry.input).toContain("[REDACTED");
  });

  it("redacts Slack user tokens", () => {
    const dir = makeTempDir("pg-redact-slack-");
    const logPath = join(dir, "test.jsonl");
    const fakeSlackToken = [
      "xoxp",
      "123456789012",
      "123456789012",
      "1234567890123",
      "abcdef1234567890abcdef1234567890",
    ].join("-");
    logDecision("bash", `export SLACK_TOKEN=${fakeSlackToken}`, "allow", "test", logPath);
    const entry = JSON.parse(readFileSync(logPath, "utf8").trim());
    expect(entry.input).not.toContain("xoxp-");
    expect(entry.input).toContain("[REDACTED");
  });

  it("redacts JWT tokens", () => {
    const dir = makeTempDir("pg-redact-jwt-");
    const logPath = join(dir, "test.jsonl");
    logDecision(
      "bash",
      "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'",
      "allow",
      "test",
      logPath,
    );
    const entry = JSON.parse(readFileSync(logPath, "utf8").trim());
    expect(entry.input).not.toContain("eyJhbGci");
    expect(entry.input).toContain("[REDACTED");
  });

  it("leaves safe inputs unchanged", () => {
    const dir = makeTempDir("pg-redact-safe-");
    const logPath = join(dir, "test.jsonl");
    const safeInput = "bin/gitlab-query upstream /pipelines --source schedule";
    logDecision("bash", safeInput, "allow", "test", logPath);
    const entry = JSON.parse(readFileSync(logPath, "utf8").trim());
    expect(entry.input).toBe(safeInput);
  });

  it("redacts AWS access keys", () => {
    const dir = makeTempDir("pg-redact-aws-");
    const logPath = join(dir, "test.jsonl");
    logDecision("bash", "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "allow", "test", logPath);
    const entry = JSON.parse(readFileSync(logPath, "utf8").trim());
    expect(entry.input).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(entry.input).toContain("[REDACTED");
  });

  it("redacts AWS secret access key by variable name", () => {
    const dir = makeTempDir("pg-redact-aws-secret-");
    const logPath = join(dir, "test.jsonl");
    logDecision(
      "bash",
      "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "allow",
      "test",
      logPath,
    );
    const entry = JSON.parse(readFileSync(logPath, "utf8").trim());
    expect(entry.input).not.toContain("wJalrXUtnFEMI");
    expect(entry.input).toContain("[REDACTED");
  });

  it("redacts generic PASSWORD= assignments", () => {
    const dir = makeTempDir("pg-redact-pass-");
    const logPath = join(dir, "test.jsonl");
    logDecision("bash", "export DB_PASSWORD=supersecret123", "allow", "test", logPath);
    const entry = JSON.parse(readFileSync(logPath, "utf8").trim());
    expect(entry.input).not.toContain("supersecret123");
    expect(entry.input).toContain("[REDACTED");
  });

  it("redacts PRIVATE_KEY= assignments", () => {
    const dir = makeTempDir("pg-redact-privkey-");
    const logPath = join(dir, "test.jsonl");
    logDecision(
      "bash",
      "GITLAB_PRIVATE_TOKEN=glpat-abcdefghij1234567890",
      "allow",
      "test",
      logPath,
    );
    const entry = JSON.parse(readFileSync(logPath, "utf8").trim());
    expect(entry.input).not.toContain("glpat-abcdefghij");
    expect(entry.input).toContain("[REDACTED");
  });

  it("redacts DATABASE_URL connection strings", () => {
    const dir = makeTempDir("pg-redact-dburl-");
    const logPath = join(dir, "test.jsonl");
    logDecision(
      "bash",
      "export DATABASE_URL=postgres://user:pass123@db.example.com:5432/mydb",
      "allow",
      "test",
      logPath,
    );
    const entry = JSON.parse(readFileSync(logPath, "utf8").trim());
    expect(entry.input).not.toContain("pass123@db.example.com");
    expect(entry.input).toContain("[REDACTED");
  });

  it("redacts secrets in the reason field too", () => {
    const dir = makeTempDir("pg-redact-reason-");
    const logPath = join(dir, "test.jsonl");
    logDecision(
      "bash",
      "curl with ghp_1234567890abcdefghijklmnopqrstuvwxyz",
      "deny",
      "'curl with ghp_1234567890abcdefghijklmnopqrstuvwxyz' matches deny",
      logPath,
    );
    const entry = JSON.parse(readFileSync(logPath, "utf8").trim());
    expect(entry.input).not.toContain("ghp_1234567890");
    expect(entry.reason).not.toContain("ghp_1234567890");
    expect(entry.reason).toContain("[REDACTED");
  });
});
