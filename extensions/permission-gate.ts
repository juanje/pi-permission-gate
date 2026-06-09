/**
 * Pi Permission Gate Extension
 *
 * Config-driven tool restriction for Pi agents.
 * Policy: .pi/permissions.json (+ optional .pi/permissions.local.json)
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, normalize, relative } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

type Mode = "allow" | "deny";

interface PathRules {
  allow?: string[];
  deny?: string[];
}

interface ToolRule {
  default?: Mode;
  allow?: string[];
  deny?: string[];
  paths?: PathRules;
}

interface Policy {
  defaultMode: Mode;
  logPath?: string;
  permissions: {
    tools: Record<string, Mode | ToolRule>;
  };
}

const DEFAULT_POLICY: Policy = {
  defaultMode: "deny",
  permissions: { tools: {} },
};

const MAX_LOG_INPUT_LENGTH = 200;

const SELF_PROTECTED_PATHS = [
  ".pi/permissions.json",
  ".pi/permissions.local.json",
  ".pi/extensions/",
];

function isSelfProtected(path: string): boolean {
  return SELF_PROTECTED_PATHS.some((p) => path.includes(p));
}

function globToRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const regexSource = escaped.replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${regexSource}$`);
}

function expandPattern(pattern: string): string {
  return pattern.startsWith("~/") ? join(homedir(), pattern.slice(2)) : pattern;
}

function matchGlob(pattern: string, value: string): boolean {
  if (!value) return false;
  const expanded = expandPattern(pattern);
  const regex = globToRegex(expanded);
  if (regex.test(value)) return true;

  if (expanded !== pattern) {
    if (globToRegex(pattern).test(value)) return true;
  }

  const base = value.split("/").pop() ?? value;
  return regex.test(base);
}

let moduleLogPath = "";

function initLog(cwd: string, policy: Policy): string {
  const dir = policy.logPath ? join(cwd, policy.logPath) : join(cwd, ".pi", "logs");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  moduleLogPath = join(dir, `permission-gate_${ts}.jsonl`);
  return moduleLogPath;
}

function logDecision(
  tool: string,
  input: string,
  decision: "allow" | "deny",
  reason?: string,
  targetLogPath?: string,
): void {
  const path = targetLogPath ?? moduleLogPath;
  if (!path) return;
  const entry = {
    ts: new Date().toISOString(),
    tool,
    input: input.slice(0, MAX_LOG_INPUT_LENGTH),
    decision,
    reason,
  };
  try {
    appendFileSync(path, `${JSON.stringify(entry)}\n`);
  } catch {
    /* best-effort logging */
  }
}

function block(reason: string): BlockResult {
  return { block: true, reason };
}

function normalizePath(path: string, cwd: string): string {
  if (!path) return path;
  const expanded = path.startsWith("~/") ? join(homedir(), path.slice(2)) : path;
  const resolved = isAbsolute(expanded) ? relative(cwd, expanded) : normalize(expanded);
  return resolved.startsWith("..") ? expanded : resolved;
}

function extractInput(tool: string, input: Record<string, unknown>, cwd: string): string {
  switch (tool) {
    case "bash":
      return String(input.command ?? "");
    case "read":
    case "write":
    case "edit":
      return normalizePath(String(input.path ?? ""), cwd);
    case "grep":
      return String(input.pattern ?? "");
    case "find":
      return String(input.glob ?? "");
    default:
      return "";
  }
}

function loadJsonFile(path: string): Policy | null {
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as Policy;
  } catch {
    return null;
  }
}

function mergeToolRules(
  base: Mode | ToolRule | undefined,
  local: Mode | ToolRule,
): Mode | ToolRule {
  if (typeof local === "string") return local;
  if (typeof base === "string" || base === undefined) return local;

  const merged: ToolRule = { ...base, ...local };
  if (base.allow || local.allow) {
    merged.allow = [...(base.allow ?? []), ...(local.allow ?? [])];
  }
  if (base.deny || local.deny) {
    merged.deny = [...(base.deny ?? []), ...(local.deny ?? [])];
  }
  if (base.paths || local.paths) {
    merged.paths = {
      allow: [...(base.paths?.allow ?? []), ...(local.paths?.allow ?? [])],
      deny: [...(base.paths?.deny ?? []), ...(local.paths?.deny ?? [])],
    };
  }
  return merged;
}

function mergePolicies(base: Policy | null, local: Policy | null): Policy {
  if (!base && !local) return DEFAULT_POLICY;
  if (!base) return local ?? DEFAULT_POLICY;
  if (!local) return base;

  const merged: Policy = {
    defaultMode: local.defaultMode ?? base.defaultMode,
    permissions: { tools: { ...base.permissions.tools } },
  };

  for (const [tool, localRule] of Object.entries(local.permissions?.tools ?? {})) {
    merged.permissions.tools[tool] = mergeToolRules(base.permissions.tools[tool], localRule);
  }

  return merged;
}

function loadPolicy(cwd: string): Policy {
  const base = loadJsonFile(join(cwd, ".pi", "permissions.json"));
  const local = loadJsonFile(join(cwd, ".pi", "permissions.local.json"));
  return mergePolicies(base, local);
}

function isToolAllowedAtSessionLevel(toolName: string, policy: Policy): boolean {
  const rule = policy.permissions.tools[toolName];
  if (rule === "deny") return false;
  if (rule === "allow") return true;
  if (rule === undefined) return policy.defaultMode !== "deny";
  return true;
}

type BlockResult = { block: true; reason: string };

function evaluateToolCall(
  toolName: string,
  input: Record<string, unknown>,
  policy: Policy,
  cwd: string,
): BlockResult | undefined {
  const rule = policy.permissions.tools[toolName];

  if (rule === "deny") {
    const reason = `Tool '${toolName}' is denied`;
    logDecision(toolName, "", "deny", reason);
    return block(reason);
  }
  if (rule === "allow") {
    logDecision(toolName, "", "allow");
    return undefined;
  }

  if (rule === undefined) {
    if (policy.defaultMode === "deny") {
      const reason = `Tool '${toolName}' not in allowlist`;
      logDecision(toolName, "", "deny", reason);
      return block(reason);
    }
    logDecision(toolName, "", "allow", "defaultMode");
    return undefined;
  }

  const value = extractInput(toolName, input, cwd);

  if (rule.deny?.some((pattern) => matchGlob(pattern, value))) {
    const reason = `'${value}' matches deny pattern for ${toolName}`;
    logDecision(toolName, value, "deny", reason);
    return block(reason);
  }

  if (rule.paths?.deny?.some((pattern) => matchGlob(pattern, value))) {
    const reason = `Path '${value}' is protected`;
    logDecision(toolName, value, "deny", reason);
    return block(reason);
  }

  if (rule.allow?.some((pattern) => matchGlob(pattern, value))) {
    logDecision(toolName, value, "allow", "allow pattern");
    return undefined;
  }
  if (rule.paths?.allow?.some((pattern) => matchGlob(pattern, value))) {
    logDecision(toolName, value, "allow", "path allow pattern");
    return undefined;
  }

  const toolDefault = rule.default ?? policy.defaultMode;
  if (toolDefault === "deny") {
    const reason = `'${value}' not in allowlist for ${toolName}`;
    logDecision(toolName, value, "deny", reason);
    return block(reason);
  }
  logDecision(toolName, value, "allow", "tool default");
  return undefined;
}

export default function (pi: ExtensionAPI) {
  let policy: Policy = DEFAULT_POLICY;
  let projectCwd = "";

  pi.on("session_start", async (_event, ctx) => {
    projectCwd = ctx.cwd;
    policy = loadPolicy(projectCwd);
    initLog(projectCwd, policy);
  });

  pi.on("before_agent_start", async (_event, _ctx) => {
    const allowed = pi
      .getAllTools()
      .map((tool) => tool.name)
      .filter((name) => isToolAllowedAtSessionLevel(name, policy));
    pi.setActiveTools(allowed);
  });

  pi.on("tool_call", async (event, _ctx) => {
    const input = extractInput(event.toolName, event.input, projectCwd);
    if (input && isSelfProtected(input)) {
      const reason = "Permission gate config and extensions are self-protected";
      logDecision(event.toolName, input, "deny", reason);
      return block(reason);
    }
    return evaluateToolCall(event.toolName, event.input, policy, projectCwd);
  });
}

export type { BlockResult, Mode, PathRules, Policy, ToolRule };
export {
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
  SELF_PROTECTED_PATHS,
};
