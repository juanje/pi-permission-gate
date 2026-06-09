# pi-permission-gate

Config-driven permission system for [Pi](https://pi.dev) agents. Deny-by-default tool restriction with glob matching, path normalization, self-protection, and structured logging.

## Install

From npm:

```bash
pi install npm:pi-permission-gate
```

From git:

```bash
pi install git+https://github.com/juanje/pi-permission-gate.git
```

Or load directly without installing:

```bash
pi -e /path/to/pi-permission-gate/extensions/permission-gate.ts
```

## Quick start

Create `.pi/permissions.json` in your project:

```json
{
  "defaultMode": "deny",
  "permissions": {
    "tools": {
      "read": { "paths": { "allow": ["**"] }, "default": "allow" },
      "write": { "paths": { "allow": ["tmp/*"] }, "default": "deny" },
      "bash": {
        "allow": ["date", "date *", "git *", "bin/*"],
        "deny": ["rm *", "curl *", "wget *", "*.env*"],
        "default": "deny"
      }
    }
  }
}
```

Optional local overrides in `.pi/permissions.local.json` (gitignored).

## How it works

The extension hooks into three Pi events:

1. **`session_start`** — loads and merges policy files, initializes the permission log
2. **`before_agent_start`** — hides tools blocked at session level via `setActiveTools()`
3. **`tool_call`** — enforces granular rules before each tool executes

### Evaluation order

For each tool call:

1. **Self-protection** — blocks operations on `.pi/permissions.json`, `.pi/permissions.local.json`, and `.pi/extensions/` (hardcoded, cannot be overridden)
2. **Simple rules** — `"allow"` or `"deny"` for the entire tool
3. **Deny patterns** — command/path glob patterns (deny always wins)
4. **Allow patterns** — command/path glob patterns
5. **Tool default** — per-tool `default` mode
6. **Policy default** — global `defaultMode`

### Glob matching

Patterns use `*` (any sequence) and `?` (single character). Tilde expansion is supported in patterns (`~/.ssh/*`). Paths are normalized (`~`, `./`, `../`, absolute → relative) before matching.

### Structured log

Each decision is appended to `.pi/logs/permission-gate_{timestamp}.jsonl`:

```json
{"ts":"2026-06-09T00:05:16.733Z","tool":"bash","input":"cat .env","decision":"deny","reason":"'cat .env' matches deny pattern for bash"}
```

Custom log directory via `logPath` in the policy:

```json
{
  "defaultMode": "deny",
  "logPath": "var/audit",
  "permissions": { "tools": {} }
}
```

## Policy format

```typescript
interface Policy {
  defaultMode: "allow" | "deny";
  logPath?: string; // optional, relative to project root
  permissions: {
    tools: Record<string, "allow" | "deny" | ToolRule>;
  };
}

interface ToolRule {
  default?: "allow" | "deny";
  allow?: string[];   // glob patterns (bash commands, etc.)
  deny?: string[];
  paths?: {
    allow?: string[];
    deny?: string[];
  };
}
```

### Merge strategy

When both `.pi/permissions.json` and `.pi/permissions.local.json` exist:

- `defaultMode` — local wins
- Tool rules — deep merged (arrays concatenated)
- Local string rule (`"allow"` / `"deny"`) — overrides base entirely

## Development

```bash
git clone https://github.com/juanje/pi-permission-gate.git
cd pi-permission-gate
npm install
npm run check    # typecheck + lint + test
```

## License

MIT — see [LICENSE](LICENSE).
