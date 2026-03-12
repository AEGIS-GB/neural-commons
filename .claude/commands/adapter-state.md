# Adapter State Report

Read the adapter configuration and source code to report the current operational state. Do not modify any code.

## What to Report

### 1. Current Mode

Read `adapter/aegis-adapter/src/config.rs` and `adapter/aegis-proxy/src/config.rs` to determine:
- What is the default mode? (observe_only / enforce / pass_through)
- What modes are available?
- How is the mode set? (config file, CLI flag override)

### 2. Protection Enforcement Status (D30)

Read `adapter/aegis-adapter/src/server.rs` (the `create_middleware_hooks` function and enforcement config) to report which protections are active vs warn-only:

Per D30 defaults:
- `write_barrier` — **observe** by default (warns but does not block)
- `slm_reject` — **observe** by default (warns but does not block)
- `vault_block` — **always enforce** (blocks on credential detection)
- `memory_write` — **always enforce** (blocks on suspicious memory writes)

Check `adapter/aegis-adapter/src/config.rs` for the enforcement config structure and defaults.

### 3. SLM Status

Read `adapter/aegis-slm/src/ollama.rs` and `adapter/aegis-adapter/src/hooks.rs` to report:
- Is SLM enabled? (check `config.slm.enabled` in server.rs)
- What Ollama URL is configured? (default: `http://127.0.0.1:11434`)
- What model is configured? (default: `llama3.2:1b`)
- Is heuristic fallback enabled? (default: `true`)
- What happens when `--no-slm` is passed? (check CLI and server.rs)

### 4. Protected Files

Read `adapter/aegis-barrier/src/protected_files.rs` to list all system-protected files:
- List every pattern in `ProtectedFileManager::new()` system_files
- For each: pattern, scope (WorkspaceRoot/DepthLimited), critical (yes/no), sensitivity (Standard/Credential)
- What is the max watched paths cap? (check `MAX_WATCHED_PATHS` in types.rs)

### 5. Config Values in Effect

Read `adapter/aegis-adapter/src/config.rs` and `adapter/aegis-proxy/src/config.rs` to report all default values:
- Listen address
- Upstream URL
- Max body size
- Rate limit per minute
- SLM model and URL
- Memory hash interval
- Dashboard path

## Output Format

```
## Aegis Adapter State Report

### Mode
- Current default: [observe_only/enforce/pass_through]
- Override: [how to override via CLI]

### Protection Enforcement (D30)
| Protection    | Default    | Effect                          |
|---------------|------------|---------------------------------|
| write_barrier | observe    | Warns on protected file changes |
| slm_reject    | observe    | Warns on injection detection    |
| vault_block   | enforce    | Blocks credential leaks         |
| memory_write  | enforce    | Blocks suspicious memory writes |

### SLM Status
- Enabled: [yes/no]
- Ollama URL: [url]
- Model: [model name]
- Heuristic fallback: [yes/no]
- --no-slm behavior: [description]

### Protected Files (System Defaults)
| Pattern       | Scope          | Critical | Sensitivity |
|---------------|----------------|----------|-------------|
| SOUL.md       | WorkspaceRoot  | yes      | Standard    |
| ...           | ...            | ...      | ...         |

### Config Defaults
| Key                    | Default Value               |
|------------------------|-----------------------------|
| proxy.listen_addr      | 127.0.0.1:3141             |
| proxy.upstream_url     | https://api.anthropic.com  |
| ...                    | ...                         |
```
