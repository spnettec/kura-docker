#!/usr/bin/env python3
# SPDX-License-Identifier: EPL-2.0
"""Container credentials and persistent state; never replace an unverified old key."""
import base64
import contextlib
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

FACTORY = Path("/usr/local/share/kura/image-state.json")
OPTION_NAMES = ("JAVA_OPTS", "JAVA_INT_OPTS", "JDK_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS")
TLS_NAME = "user/security/httpskeystore.ks"
MAX_STATE_BYTES = 16 * 1024 * 1024


def load_policy(home):
    spec = importlib.util.spec_from_file_location("kura_container_key_policy", home / "bin/kura_key_store.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inventory(home, output=FACTORY):
    # A server private key must never be copied into an image layer.
    if (home / TLS_NAME).exists():
        raise RuntimeError("Server private keystore cannot be included in the image")
    files = {}
    for name in ("user", "data", "packages"):
        for path in sorted((home / name).rglob("*")):
            if path.is_symlink():
                raise RuntimeError("Factory state must not contain symlinks")
            if path.is_file():
                files[str(path.relative_to(home))] = hashlib.sha256(path.read_bytes()).hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(dict(schema=1, files=files), sort_keys=True) + "\n")


def properties_values(raw):
    """Decode bounded Java Properties values, including continuation and escapes."""
    text = raw.decode("iso-8859-1")
    logical = []
    pending = ""
    for line in text.splitlines():
        line = line.lstrip(" \t\f") if pending else line
        value = pending + line
        count = len(value) - len(value.rstrip("\\"))
        if count % 2:
            pending = value[:-1]
        else:
            logical.append(value)
            pending = ""
    if pending:
        raise ValueError("Incomplete properties continuation")

    def unescape(value):
        def replace(match):
            token = match.group(1)
            return chr(int(token[1:], 16)) if token.startswith("u") else {
                "t": "\t", "n": "\n", "r": "\r", "f": "\f"}.get(token, token)
        if re.search(r"\\u(?![0-9a-fA-F]{4})", value):
            raise ValueError("Invalid properties escape")
        return re.sub(r"\\(u[0-9a-fA-F]{4}|.)", replace, value)

    values = []
    for line in logical:
        line = line.lstrip(" \t\f")
        if not line or line[0] in "#!":
            continue
        escaped = False
        split = len(line)
        for index, char in enumerate(line):
            if not escaped and char in "=:\t\f ":
                split = index
                break
            escaped = not escaped if char == "\\" else False
        tail = line[split:].lstrip(" \t\f")
        if tail[:1] in ("=", ":"):
            tail = tail[1:].lstrip(" \t\f")
        values.append(unescape(tail))
    if len(values) > 4096:
        raise ValueError("Too many properties entries")
    return values


class Bootstrap:
    def __init__(self, home, persistent, environ=None, factory=None, policy=None):
        self.home = Path(home).absolute()
        self.root = Path(persistent).absolute()
        self.env = dict(os.environ if environ is None else environ)
        self.policy = policy or load_policy(self.home)
        self.store = self.policy.Store(self.root)
        self.factory = factory if factory is not None else json.loads(FACTORY.read_text())["files"]
        self.marker = self.store.path("/etc/kura/credentials/container-bootstrap.json")
        self.sanitized = {}

    def require(self, condition, message):
        self.policy.require(condition, message)

    def read_data(self, path):
        metadata = path.lstat()
        return self.store.read(path, limit=MAX_STATE_BYTES, owners={metadata.st_uid})

    def state_files(self):
        result = {}
        for origin in (self.home, self.root):
            for name in ("user", "data", "packages"):
                directory = origin / name
                if directory.is_symlink():
                    self.require(origin == self.home and directory.resolve() == (self.root / name).resolve(),
                                 "Unreviewed container state alias")
                    continue
                if not directory.exists():
                    continue
                for path in sorted(directory.rglob("*")):
                    self.require(not path.is_symlink(), "Container state contains a symlink")
                    if path.is_file():
                        relative = str(path.relative_to(origin))
                        data = self.read_data(path)
                        factory = self.factory.get(relative) == hashlib.sha256(data).hexdigest()
                        if relative in result:
                            self.require(factory or result[relative][2] or result[relative][1] == data,
                                         "Container state locations disagree")
                        if relative not in result or not factory or result[relative][2]:
                            result[relative] = (path, data, factory)
        return result

    def explicit_key(self):
        properties = []
        for name in OPTION_NAMES:
            raw = self.env.get(name, "")
            tokens = shlex.split(raw)
            safe = []
            for token in tokens:
                self.require(not token.startswith("@"), "JVM argument files require reviewed key import")
                if token.startswith("-D" + self.policy.PROPERTY):
                    self.require(token.startswith("-D" + self.policy.PROPERTY + "="),
                                 "Unsupported legacy JVM encryption option")
                    value = token.split("=", 1)[1]
                    self.require(not any(char in value for char in ("$", chr(96), "\n", "\r")),
                                 "Dynamic legacy JVM encryption source requires reviewed import")
                    if value:
                        properties.append(self.policy.effective_key(value.encode("utf-8")))
                else:
                    safe.append(token)
            self.sanitized[name] = shlex.join(safe)
        self.require(not properties or all(value == properties[0] for value in properties),
                     "Legacy JVM encryption sources disagree")
        credential_dir = self.env.get("CREDENTIALS_DIRECTORY", "")
        if credential_dir:
            self.require(Path(credential_dir).is_absolute(), "Credential source must be absolute")
            value = self.store.key(Path(credential_dir) / self.policy.CREDENTIAL)
            return value
        if properties:
            return properties[0]
        value = self.env.get("KURA_CRYPTO_SECRET_KEY", "")
        return self.policy.effective_key(value.encode("utf-8")) if value else None

    def envelopes(self, files):
        envelopes = []
        for relative, (_, data, _) in files.items():
            if relative == "data/store.save":
                envelopes.extend(value for value in properties_values(data) if value)
            elif re.fullmatch(r"user/snapshots/snapshot_[0-9]+\.xml", relative):
                if data.lstrip().startswith(b"<"):
                    self.require(b"<!DOCTYPE" not in data.upper(), "Unsupported snapshot document type")
                    root = ET.fromstring(data)
                    envelopes.extend((node.text or "").strip() for node in root.iter()
                                     if re.fullmatch(r"[A-Za-z0-9+/]{16}-[A-Za-z0-9+/=]+", (node.text or "").strip()))
                else:
                    envelopes.append(data.decode("ascii"))
        return envelopes

    def authenticates(self, candidate, envelopes):
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        for envelope in envelopes:
            try:
                nonce, ciphertext = envelope.split("-", 1)
                nonce = base64.b64decode(nonce, validate=True)
                ciphertext = base64.b64decode(ciphertext, validate=True)
                self.require(len(nonce) == 12 and len(ciphertext) >= 16, "Invalid legacy encrypted state")
                AESGCM(candidate).decrypt(nonce, ciphertext, None)
            except InvalidTag:
                return False
        return True

    def authenticated_legacy_key(self, files):
        # Empty/plaintext state never justifies assuming a historical default.
        envelopes = self.envelopes(files)
        self.require(bool(envelopes), "Existing container data has no verifiable encryption-key source")
        matches = []
        for candidate in dict.fromkeys((self.policy.OLD_DEVELOPMENT, self.policy.CORE_DEFAULT)):
            if self.authenticates(candidate, envelopes):
                matches.append(candidate)
        self.require(len(matches) == 1, "Legacy encrypted data does not match one verified historical key")
        return matches[0]

    def merge_and_alias(self, files):
        for name in ("user", "data", "packages"):
            self.store.private_dir(self.root / name)
        for relative, (_, data, _) in files.items():
            target = self.root / relative
            self.require(not target.exists() or self.read_data(target) == data,
                         "Persistent state requires explicit collision reconciliation")
            if not target.exists():
                self.store.publish(target, data, 0o600)
        for name in ("user", "data", "packages"):
            source, target = self.home / name, self.root / name
            if source.is_symlink():
                self.require(source.resolve() == target.resolve(), "Container alias changed")
            else:
                if source.exists():
                    backup = self.home / (".container-original-" + name)
                    self.require(not os.path.lexists(backup), "Prior container state backup requires reconciliation")
                    self.archive_directory(source, backup)
                    self.store.observed = {path: row for path, row in self.store.observed.items()
                                           if source not in path.parents}
                source.symlink_to(target, target_is_directory=True)

    def archive_directory(self, source, backup):
        try:
            source.rename(backup)
            return
        except OSError as error:
            if error.errno != errno.EXDEV:
                raise
        # OverlayFS cannot rename a directory from an image's lower layer.
        # Keep the source until its complete private backup is verified and durable.
        shutil.copytree(source, backup, copy_function=shutil.copy2)
        original = {str(path.relative_to(source)) for path in source.rglob("*")}
        copied = {str(path.relative_to(backup)) for path in backup.rglob("*")}
        self.require(original == copied, "Incomplete container state archive")
        for relative in sorted(original):
            before, after = source / relative, backup / relative
            metadata = before.lstat()
            self.require(not before.is_symlink() and not after.is_symlink(), "Unsafe container archive alias")
            self.require(before.is_dir() == after.is_dir(), "Container archive file type changed")
            os.chown(after, metadata.st_uid, metadata.st_gid, follow_symlinks=False)
            if before.is_file():
                self.require(self.read_data(before) == self.read_data(after), "Container archive bytes changed")
                with after.open("rb") as saved:
                    os.fsync(saved.fileno())
            else:
                self.require(before.is_dir(), "Unsupported container archive file type")
        metadata = source.stat()
        os.chown(backup, metadata.st_uid, metadata.st_gid, follow_symlinks=False)
        for directory in [*sorted((path for path in backup.rglob("*") if path.is_dir()),
                                  key=lambda path: len(path.parts), reverse=True), backup, backup.parent.resolve()]:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        self.store.stable()
        shutil.rmtree(source)

    @contextlib.contextmanager
    def instance_locked(self):
        self.require(self.root.is_absolute() and self.root != self.home and ".." not in self.root.parts
                     and self.root not in self.home.parents and self.home not in self.root.parents,
                     "Invalid persistent container directory")
        import fcntl
        with self.store.locked():
            lock = self.root / "etc/kura/credentials/.instance.lock"
            fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                metadata = os.fstat(fd)
                self.require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                             and metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o077,
                             "Unsafe container instance lock")
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BaseException:
                os.close(fd)
                raise
        try:
            yield fd
        finally:
            os.close(fd)

    def prepare(self, keytool=subprocess.run):
        with self.instance_locked():
            return self.prepare_locked(keytool)

    def prepare_locked(self, keytool=subprocess.run):
        with self.store.locked():
            files = self.state_files()
            for relative, (_, data, _) in files.items():
                target = self.root / relative
                self.require(not target.exists() or self.read_data(target) == data,
                             "Persistent state requires explicit collision reconciliation")
            existing = any(not row[2] for row in files.values())
            canonical = self.store.path(self.policy.KEY_PATH)
            current = self.store.key(canonical) if os.path.lexists(canonical) else None
            receipt_path = self.store.path(self.policy.RECEIPT_PATH)
            receipt = json.loads(self.store.read(receipt_path, private=True)) if receipt_path.exists() else None
            if receipt is not None:
                self.require(current is not None and receipt.get("schema") == 1
                             and set(receipt) == {"schema", "keySha256", "origin", "legacyKey", "unitDigests"}
                             and receipt.get("keySha256") == hashlib.sha256(current).hexdigest()
                             and receipt.get("origin") in ("fresh", "legacy", "canonical")
                             and receipt.get("legacyKey") == (current in (self.policy.OLD_DEVELOPMENT, self.policy.CORE_DEFAULT))
                             and isinstance(receipt.get("unitDigests"), list)
                             and len(receipt["unitDigests"]) <= 3
                             and all(isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest)
                                     for digest in receipt["unitDigests"]),
                             "Container key receipt is inconsistent")
            marker = json.loads(self.store.read(self.marker, private=True)) if self.marker.exists() else None
            if marker is not None:
                self.require(current is not None and marker.get("schema") == 1
                             and set(marker) == {"schema", "keySha256"}
                             and marker.get("keySha256") == hashlib.sha256(current).hexdigest(),
                             "Container bootstrap identity changed")
                self.require(TLS_NAME in files, "Existing container HTTPS private key is missing")
            # An upgrade must retain the existing TLS key as well as its data key.
            self.require(not existing or TLS_NAME in files, "Existing container state requires its original HTTPS keystore")
            selected = self.explicit_key()
            if current is not None and selected is not None:
                self.require(current == selected, "Canonical and supplied container encryption keys disagree")
            if current is None and selected is None and existing:
                selected = self.authenticated_legacy_key(files)
            value = current if current is not None else selected
            origin = "canonical" if current is not None else "legacy"
            if value is None:
                value, origin = secrets.token_bytes(32), "fresh"
            if existing:
                self.require(self.authenticates(value, self.envelopes(files)),
                             "Container encrypted state does not match its key")
            self.store.stable()
            if current is None:
                self.store.publish(canonical, value)
            if receipt is None:
                receipt = dict(schema=1, keySha256=hashlib.sha256(value).hexdigest(), origin=origin,
                               legacyKey=value in (self.policy.OLD_DEVELOPMENT, self.policy.CORE_DEFAULT), unitDigests=[])
                self.store.publish(receipt_path, (json.dumps(receipt, sort_keys=True) + "\n").encode(), 0o600)
            self.merge_and_alias(files)
            tls = self.root / TLS_NAME
            if not tls.exists():
                self.store.private_dir(tls.parent)
                with tempfile.TemporaryDirectory(prefix=".tls-", dir=tls.parent) as temporary:
                    generated = Path(temporary) / "httpskeystore.ks"
                    command = ["keytool", "-J-Dfile.encoding=UTF-8", "-genkeypair", "-alias", "localhost",
                               "-keyalg", "RSA", "-keysize", "2048", "-storetype", "PKCS12",
                               "-keystore", str(generated), "-dname",
                               "CN=YOFC, OU=信息技术部, O=长飞光纤光缆股份有限公司, L=武汉, S=湖北, C=中国",
                               "-ext", "ku=digitalSignature,keyEncipherment", "-ext", "eku=serverAuth",
                               "-validity", "1000", "-storepass", "changeit", "-keypass", "changeit"]
                    result = keytool(command, capture_output=True,
                                     env=dict(os.environ, LANG="C.UTF-8", LC_ALL="C.UTF-8"))
                    self.require(result.returncode == 0, "Container HTTPS keystore generation failed")
                    self.store.publish(tls, generated.read_bytes(), 0o600)
            if marker is None:
                marker = dict(schema=1, keySha256=hashlib.sha256(value).hexdigest())
                self.store.publish(self.marker, (json.dumps(marker, sort_keys=True) + "\n").encode(), 0o600)
            return dict(keyReady=True, source=receipt["origin"], legacyKey=receipt["legacyKey"],
                        credentialDirectory=str(canonical.parent), persistentDirectory=str(self.root))

    def run(self, arguments):
        with self.instance_locked() as fd:
            result = self.prepare_locked()
            os.set_inheritable(fd, True)
            self.exec_runtime(result, arguments)

    def exec_runtime(self, result, arguments):
        environment = dict(self.env, CREDENTIALS_DIRECTORY=result["credentialDirectory"],
                           PERSISTENT_DIR=str(self.root), KURA_DIR=str(self.home))
        environment.pop("KURA_CRYPTO_SECRET_KEY", None)
        environment.update(self.sanitized)
        subprocess.run(["python3", "-I", str(self.home / "bin/kura_key_store.py"), "check-loaded"],
                       env=environment, check=True)
        configuration = Path("/run/kura-container/configuration")
        self.store.private_dir(configuration)
        with (configuration / "config.ini").open("wb") as output:
            subprocess.run([str(self.home / "bin/gen_config_ini.sh"), str(self.home / "framework/config.ini"),
                            str(self.home / "plugins"), str(self.home / "siblings")], stdout=output, check=True)
        launchers = list((self.home / "plugins").rglob("org.eclipse.equinox.launcher-*.jar"))
        self.require(len(launchers) == 1, "Container requires one Equinox launcher")
        options = shlex.split(self.sanitized.get("JAVA_OPTS", "")) + shlex.split(self.sanitized.get("JAVA_INT_OPTS", ""))
        options += ["-XX:+IgnoreUnrecognizedVMOptions", "--add-opens", "java.base/java.lang=ALL-UNNAMED",
                    "--add-opens", "java.base/java.util=ALL-UNNAMED", "--add-modules=ALL-SYSTEM",
                    "-Declipse.ignoreApp=true", "-Declipse.consoleLog=true", "-Dosgi.console=9000",
                    "-Dkura.os.version=centos", "-Dkura.arch=intel-up2-centos-7", "-Dtarget.device=intel-up2-nn",
                    "-Dkura.model.id=Docker", "-Dkura.model.name=Docker", "-Dkura.serialNumber=Docker",
                    "-Dkura.bios.version=Docker", "-Dkura.firmware.version=Docker",
                    "-Dkura.device.name=" + self.env.get("KURA_DEVICE_NAME", "Kura Container Instance"),
                    "-Dkura.home=" + str(self.home), "-Dkura.data=" + str(self.home / "data"),
                    "-Dkura.snapshots=" + str(self.home / "user/snapshots"),
                    "-Dkura.packages=" + str(self.home / "packages"),
                    "-Ddpa.configuration=" + str(self.home / "packages/dpa.properties"),
                    "-Dkura.configuration=file:" + str(self.home / "framework/kura.properties"),
                    "-Dkura.custom.configuration=file:" + self.env.get("KURA_CUSTOM_PROPERTIES_FILE", str(self.home / "user/kura_custom.properties")),
                    "-Dlog4j.configurationFile=file:" + self.env.get("KURA_LOG4J_FILE", str(self.home / "log4j/log4j.xml"))]
        os.execvpe("/usr/bin/java", ["/usr/bin/java", *options, "-jar", str(launchers[0]),
                    "-configuration", str(configuration), *arguments], environment)


def main(arguments):
    try:
        home = Path(os.environ.get("KURA_DIR", "/opt/eclipse/kura"))
        if arguments == ["inventory"]:
            inventory(home)
            return 0
        if not arguments or arguments[0] not in ("prepare", "run") or os.geteuid() != 0:
            raise RuntimeError("Unsupported container bootstrap invocation")
        bootstrap = Bootstrap(home, Path(os.environ.get("PERSISTENT_DIR") or "/var/lib/kura"))
        if arguments[0] == "prepare":
            bootstrap.prepare()
            print("Kura container credentials and persistent state are ready.")
        else:
            bootstrap.run(arguments[1:])
        return 0
    except Exception:
        # Never log options, key values, protected plaintext, or keytool command output.
        print("Kura container bootstrap refused; preserve existing keys/data and reconcile the migration source.",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
