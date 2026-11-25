# AGENTS.md — kura-docker

Docker image sibling for Eclipse Kura. Produces `kura-alpine:latest` by pulling `.deb` packages from `~/.m2` and installing them via `dpkg -x` inside an Alpine container.

## Architecture

Unlike the previous monorepo approach (which assembled bundles individually via Maven copy), this sibling consumes **pre-built `.deb` packages** — the same packages installed on real hardware. This ensures Docker and bare-metal installations are byte-identical.

### What gets installed

| Package | Source | Contents |
|---------|--------|----------|
| `kura-core.deb` | `org.eclipse.kura:gateway:6.0.0-SNAPSHOT:deb` | Core runtime, plugins, framework |
| `kura-management-ui.deb` | `org.eclipse.kura:kura-management-ui-distrib:3.0.0-SNAPSHOT:deb` | Web UI (web2) + commons-csv + console favicons |
| `kura-deployment.deb` | `org.eclipse.kura:kura-deployment.distrib:2.0.0-SNAPSHOT:deb` | Deployment agent + REST packages |
| yofc `.dp` files | `com.yofc.iot:yofc-iot-*:0.0.1-SNAPSHOT:dp` | Optional deployment packages (gated by `-Ddist.dp.skip=false`) |

### Why `dpkg -x` instead of `dpkg -i`

The kura-core `.deb` postinst calls `systemctl`, `timedatectl`, etc. which are unavailable in Docker. We extract files only (`dpkg -x`) and run `docker-setup.sh` to handle Docker-specific setup (users, directories, keystore generation, snapshot copy).

## Build

```bash
# Prerequisites (from build-all.sh stages 1-3):
# ~/.m2 must contain kura-core.deb + sibling .debs

mvn -f kura-docker/pom.xml clean install
```

### Add a sibling to the Docker image

1. Add a `<artifactItem>` in `pom.xml` under `copy-sibling-debs`
2. Add `dpkg -x /tmp/debs/<name>.deb /` in the Dockerfile
3. Add `echo "<sibling-name>"` to the sibling-install-order section

### Build with yofc .dp packages

```bash
mvn -f kura-docker/pom.xml clean install -Ddist.dp.skip=false
```

## File Layout

```
kura-docker/
├── pom.xml                     # Maven build: copies .debs, runs docker build
├── docker-setup.sh             # Docker-specific post-install setup
└── src/main/resources/
    ├── Dockerfile              # Alpine + dpkg -x installation
    └── bin/                    # Runtime scripts (entry-point, dp-install, etc.)
```

## Run

```bash
docker run -d -p 443:443 --name kura kura-alpine:latest
```

Access the management UI at `https://localhost:443` (default credentials: `admin` / `admin`).

## Codebase Memory MCP — Code Intelligence

This project is indexed by **codebase-memory-mcp**. Always use it BEFORE grep/find or reading files when you need to understand or locate code. The skill at `~/.claude/skills/codebase-memory/` contains the full decision matrix and workflow.

### Quick Reference

| Question | Tool |
|----------|------|
| Who calls X? | `trace_path(direction="inbound")` |
| What does X call? | `trace_path(direction="outbound")` |
| Find by name | `search_graph(name_pattern="...")` |
| Dead code | `search_graph(max_degree=0)` |
| Impact of changes | `detect_changes()` |
| Architecture overview | `get_architecture(aspects=["all"])` |
| Read source | `get_code_snippet(qualified_name="...")` |

### Exploration Workflow

`list_projects` → `get_graph_schema` → `search_graph` → `get_code_snippet`

> If the repository hasn't been indexed yet, run: `codebase-memory-mcp cli index_repository '{"repo_path": "/path/to/repo"}'`

### Stopped-volume recovery for a legacy PKCS12 password change

Older filesystem keystore providers published two private names for one encrypted recovery record using a hard link. A container interrupted at that point refuses normal startup. Use the maintenance image containing both the updated launcher and keystore provider, with the original stopped volume mounted at its original destination. Take the root device and inode, OSGi keystore PID, exact configured absolute keystore path and SHA-256 of the encrypted record from the same installation. The command acquires its existing instance lock and runs the provider as kurad.

```sh
docker run --rm --network none --read-only --tmpfs /tmp --tmpfs /load \
  --mount "type=volume,volume-nocopy,source=$original_volume,target=/var/lib/kura" \
  --entrypoint /usr/bin/python3 "$maintenance_image" -IB /usr/local/bin/kura-container-bootstrap.py \
  separate-keystore-links "$root_device_inode" "$keystore_pid" "$configured_store_path" "$record_sha256"
```

After a successful return, start the original instance normally. If publication was interrupted, use the same four inputs again. The provider verifies the original file identity and the two records before changing their link layout. Ordinary Main completes the pending configuration update and retires the records.

## Optional SoftHSM file-token image

Build the regular Alpine Kura image first. Then build the opt-in image using
the SoftHSM source module from the matching Core Git checkout.

```bash
docker buildx build --platform linux/arm64 --load \
  --build-arg KURA_RUNTIME_IMAGE=kura-alpine:latest \
  --build-context "softhsm-source=$CORE_REPO/kura/distrib/kura-softhsm2-file" \
  -f src/main/resources/Dockerfile.softhsm -t kura-alpine:softhsm-file src/main/resources
```

The image builds and tests a musl module from Core's verified source archive.
It inherits the regular entrypoint and mounts. Set the PKCS#11 keystore's
`library.path` to `/usr/lib/kura-pkcs11/softhsm2/libsofthsm2.so` and supply
a site configuration readable by `kurad`, mounted at
`/etc/kura-pkcs11/softhsm2-file.conf`. Keep the token directory on the
persistent volume and continue using the same slot and credential. Stop the
old container before starting a replacement against the original volume.
