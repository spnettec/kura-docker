# CLAUDE.md — kura-docker

Docker image sibling for Eclipse Kura. Produces `kura-alpine:latest` by pulling `.deb` packages from `~/.m2` and installing them via `dpkg -x` inside an Alpine container.

## Architecture

Unlike the previous monorepo approach (which assembled bundles individually via Maven copy), this sibling consumes **pre-built `.deb` packages** — the same packages installed on real hardware. This ensures Docker and bare-metal installations are byte-identical.

### What gets installed

| Package | Source | Contents |
|---------|--------|----------|
| `kura-core.deb` | `org.eclipse.kura:gateway:6.0.0-SNAPSHOT:deb` | Core runtime, plugins, framework |
| `kura-management-ui.deb` | `org.eclipse.kura:kura-management-ui-distrib:3.0.0-SNAPSHOT:deb` | Web UI (web2) + commons-csv + console favicons |
| `kura-wires.deb` | `org.eclipse.kura:kura-wires.distrib:3.0.0-SNAPSHOT:deb` | Wires data flow orchestration |
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
