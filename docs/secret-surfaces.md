# The secret-surface contract

`scrub::touches_secret_surface(text)` answers one question: does this command or tool input
handle a secret? A caller that feeds transcripts, logs or tool output to a model or a store drops
anything that does. Its knowledge comes from three layers, all combined and all additive.

**1. Built-in surfaces, always on.** `*.key` and `*.pem` files, `~/.ssh/`, `.env`, `.env.*` and
`<name>.env` files such as `prod.env` (not `.envrc` or `process.env`), `~/.netrc`,
`~/.aws/credentials`, `~/.config/gcloud/`, `~/.docker/config.json`, `~/.kube/config`,
`~/.git-credentials`, `~/.pgpass`, `~/.cargo/credentials` and `credentials.toml`,
`~/.config/gh/hosts.yml`, `~/.vault-token`, `~/.gnupg/`, `ssh-keygen`, and `git config …token`. A home-relative file matches under any spelling of the home
directory (`~/`, `$HOME/`, an absolute path).

**2. Your deployment's surfaces, from a file.** `scrub::init()` reads the first of:

1. `$NUVEK_SECRET_SURFACES_FILE`
2. `$XDG_CONFIG_HOME/nuvek/secret-surfaces.toml`
3. `~/.config/nuvek/secret-surfaces.toml`

```toml
# ~/.config/nuvek/secret-surfaces.toml
surfaces = [
    "~/.config/example-app/token",      # one file, under any spelling of $HOME
    "~/.local/share/example-app/keys/", # a directory and everything under it
    "/etc/example-app/*.secret",        # * stays within one path component
    "/srv/example-app/**/credentials",  # ** crosses components
]
```

Each entry starts with `~/` or `/` and names something (at least one letter or digit). `*` stays
within one path component, `**` crosses them (`**/` is zero or more directories), and `?` is one
character, with at most eight wildcards per entry. Wildcards match spaces, so a quoted
(`"db prod.secret"`) or backslash-escaped (`db\ prod.secret`) name is still caught, and a literal
space in an entry also matches `\ `. A wildcard never crosses a newline. Everything else is
literal, and matching is case-insensitive. `surfaces` is the only key.

An entry matches wherever its path appears in a command. A `~/` entry is matched by its
home-relative part under any prefix, so `~/.config/example-app/token` also catches
`$HOME/.config/example-app/token` and a `cd ~ && cat .config/example-app/token`. The cost is that a
very short `~/` entry such as `~/bin` also matches `/usr/bin`: name the specific file or directory.

**3. Patterns in code.** `scrub::extra_secret_surfaces([r"vault-cli\s+unseal"])` registers regex
fragments for surfaces a path cannot express, such as a CLI subcommand. It is one-shot (the first
call wins), and it works alongside the file: both stay in force, whichever was set up first.

## What `init()` guarantees

```rust
pub fn init() -> Result<InitReport, ScrubConfigError>
```

- **Call it first in `main`, before any text is scanned.**
- **Exit non-zero if it returns `Err`.** There is no silent fallback to the defaults. It fails
  when `$NUVEK_SECRET_SURFACES_FILE` is set but blank or relative, or names a file that does not
  exist, and when a file exists but is not a regular file (a directory, a FIFO, a device such as
  a link to `/dev/null`), is unreadable (permissions, a dangling symlink for it or a directory above
  it, not UTF-8), larger than 1 MiB, not valid TOML, has an unknown key, or
  has an invalid entry: empty, relative, `~user/`, too many wildcards, or one that would match
  every path (`/`, `~/`, `/*`, `~/.*`).
- **A missing file at the default location is not an error.** Only the built-ins apply, and the
  returned `InitReport` has `source: None`. `$HOME` and `$XDG_CONFIG_HOME` are used whatever their
  encoding, so a non-UTF-8 directory name never makes the file silently skipped.
- **Additive only.** Configuration can never remove a built-in.
- **Idempotent.** Calling it again re-reads the file and adds only what is new. A failed call
  leaves the surfaces already loaded in force.

`InitReport` holds the path searched, the file read, its entry count and the number of new
patterns. It contains no scanned text, so it is safe to log.

A binary that never calls `init()` still gets the built-in surfaces, but
`touches_secret_surface` logs a warning (through `tracing`) the first time it runs, and
`scrub::is_initialised()` returns `false`.
