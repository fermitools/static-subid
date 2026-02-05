# static-subid

Deterministic subordinate UID/GID assignment for unprivileged containers.

## Overview

`static-subid` calculates **predictable** subordinate UID and GID ranges for Linux users based on their UID, ensuring consistent ID mappings across multiple systems.

Unlike shadow-utils' sequential allocation (which depends on creation order), `static-subid` uses a deterministic formula that guarantees the same user UID always receives the same subordinate ID range.

Subordinate IDs enable user namespaces for unprivileged container runtimes (Podman, Docker rootless mode, LXC) by mapping container UIDs/GIDs to host subordinate IDs without requiring root privileges.

## Features

- **Deterministic allocation**: Same UID → same subordinate ID range on every system
- **Idempotent**: Safe to run multiple times, no duplicate ranges
- **Fleet-friendly**: Consistent mappings across centrally managed systems
- **Configurable**: Flexible range sizing and allocation policies

## Important Warnings

### Do Not Mix with shadow-utils

**WARNING**: `static-subid` uses a different allocation algorithm than shadow-utils `useradd` auto-assignment.

**DO NOT MIX** `static-subid` with shadow-utils auto-assignment on the same system or across systems sharing `/etc/subuid`/`/etc/subgid` via network storage (NFS, etc.). Mixing allocation methods **will cause subordinate ID range conflicts and overlaps**!

Choose one method and use it consistently across your environment.

To disable shadow-utils auto-assignment, set `SUB_UID_COUNT` and `SUB_GID_COUNT` to `0` in `/etc/login.defs`.

### Security Considerations

- Configuration files must be root-owned and not world-writable
- Range overlaps can lead to container escapes and privilege escalation
- The `ALLOW_SUBID_WRAP` option is a security risk - use **only** in controlled environments

## Quick Start

```bash
# Assign subordinate UIDs and GIDs to user alice
static-subid --subuid --subgid alice

# Dry-run to preview assignments
static-subid --subuid --subgid --noop alice

# View current configuration
static-subid --help --dump-config
```

## Documentation

See the `doc/` directory for detailed documentation:

- `static-subid(8)` - Command usage and options
- `static-subid.conf(5)` - Configuration file format and settings
- Architecture and deployment guides

## Requirements

- shadow-utils with subid support
- Root privileges for execution
- systemd-based system (for integration)

## Contributing

Report bugs and submit patches via https://github.com/fermitools/static-subid/
