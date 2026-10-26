# Changelog

All notable changes to `nuvek-core` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-26

First public release. The crate lives in its own repository (`jean1880/nuvek-core`), together
with `nuvek-chroma`, `nuvek-neo4j` and `nuvek-ollama`, under the MIT licence. It names no host,
path or deployment: every setting is a parameter supplied by the calling package.

### Added

- **`env`** (always present): `env_var`, `env_or`, `env_parse`, `env_parse_or`, `env_flag`,
  `env_dir`, `home`, `home_dir`, `expand_home`, `non_empty`, `parse_env_file` and
  `read_env_file(path, name)`, which returns a typed `EnvFileError`. Blank values count as unset
  and values are trimmed.
- **`util::command_output_timeout`**, bounded in time, memory and resources. The child runs in a
  process group of its own, and a timeout kills the whole group, so a grandchild holding the pipes
  cannot keep it waiting. The child is reaped only after that decision, so the signalled PID and
  PGID cannot have been reused. It returns within a two-second grace after a kill even if a
  descendant left the group, then stops reading and closes the pipes, leaving no thread or
  descriptor behind. At most 16 MiB of each stream is kept; the rest is drained and discarded. It
  never signals a child it can no longer observe (`ECHILD`, e.g. with `SIGCHLD` ignored), returns
  an error when `SIGKILL` is refused, and bounds the final reap, returning `TimedOut` for a child
  that has not exited by the end of the grace period. Callers must not ignore `SIGCHLD` or run a
  competing reaper.
- **`scrub`** (default feature): secret redaction and the secret-surface contract.
  `scrub::init()` reads `surfaces = [...]` from `$NUVEK_SECRET_SURFACES_FILE`, else
  `$XDG_CONFIG_HOME/nuvek/secret-surfaces.toml`, else `~/.config/nuvek/secret-surfaces.toml`.
  Entries are paths or globs (`~/…` or `/…`, with `*`, `**` and `?`). It is additive only and
  idempotent; a missing default file means built-ins only. A blank, relative or missing explicitly
  named file, an unreadable or oversized file, invalid TOML, an unknown key or an invalid entry is
  a `ScrubConfigError`. It returns an `InitReport` (paths and counts). Surfaces from `init()` and
  from `extra_secret_surfaces()` are both in force, whichever ran first. Without a successful
  `init()`, `touches_secret_surface` logs a warning once. See also `scrub::is_initialised()`,
  `scrub::SURFACES_FILE_ENV` and `scrub::SURFACES_FILE_MAX_BYTES`.
- Built-in secret surfaces: `.key`/`.pem`, `ssh-keygen`, `git config …token`, `~/.ssh/`, `.env`,
  `.env.*` and `<name>.env` (not `.envrc` or `process.env`), `~/.netrc`, `~/.aws/credentials`,
  `~/.config/gcloud/`, `~/.docker/config.json`, `~/.kube/config`, `~/.git-credentials`,
  `~/.pgpass`, `~/.cargo/credentials(.toml)`, `~/.config/gh/hosts.yml`, `~/.vault-token` and
  `~/.gnupg/`, under any spelling of the home directory.
- `scrub::redact_config` masks the password in URL userinfo
  (`postgresql://user:«REDACTED-SECRET»@host`).
- **`log`** (default feature): `get_logger(name)` writes to the systemd journal natively
  (`SYSLOG_IDENTIFIER=<name>`, real `PRIORITY`), read with `journalctl --user -t <name>`, plus a
  stderr copy unless stderr is already the journal (`JOURNAL_STREAM`). No journal socket means
  stderr only. `NUVEK_LOG_SINK=stderr|journal|auto` overrides the sink; `Logger::stderr_only(name)`
  is for tests.
- **`metrics`** (default feature): `Metrics::new(dir)` writes node_exporter textfile-collector
  `.prom` files to a directory the caller names. `Metrics::with_hit_distance` sets the retrieval
  hit threshold; `DEFAULT_HIT_DISTANCE` is public.
- **`ssh`**: `Ssh::new(host, users)` with `exec` / `exec_timeout` / `exec_as` / `exec_stdin`,
  returning a typed `SshError` (`AuthFailed` / `CommandFailed` / `Timeout` / `Spawn` /
  `PipeMissing`). The SSH client giving up does not stop the remote command, so a `Timeout` means
  "unknown, possibly still running", never "did not happen".
- **`git`** (default feature): a bounded git runner.
- **`tracing`** (default feature): `tracing::init_tracing`.
- **`gateway`** feature (`net` + `metrics`): an OpenAI-compatible chat-completions client for an
  LLM gateway tried ahead of a direct model-server call. `GatewayConfig::from_env` takes the
  variable names from the caller; `attempt()` gives the gateway 3/4 of a call's budget and the
  direct fallback whatever is actually left. Every outcome is counted as
  `llm_route_calls_total{route,reason}` (`Metrics::record_llm_route`); an empty answer is a
  fallback, not a success.
- `gateway::MODEL_NAME_HEADER` (`x-litellm-model-name`). `Answer.model` prefers it over the
  body's `model`, which the proxy restamps with the requested tier name, so a tier call reports
  the deployment that actually served it (`provider/model`). The body remains the fallback.
- `GatewayConfig.caller` (default: the executable's name; override with `with_caller()`),
  sanitised to `[a-z0-9_-]{1,64}`. Every gateway request carries it as `metadata.caller` and as a
  request tag, so callers sharing one key stay distinguishable at the gateway.
- Opt-in `net`, `mcp`, `hook` and `digest` features. Every cargo feature gates a module.

[Unreleased]: https://github.com/jean1880/nuvek-core/compare/nuvek-core-v1.0.0...HEAD
[1.0.0]: https://github.com/jean1880/nuvek-core/releases/tag/nuvek-core-v1.0.0
