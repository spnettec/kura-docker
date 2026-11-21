# SPDX-License-Identifier: EPL-2.0
"""Container key migration boundaries, independent of a running Kura gateway."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import tempfile
import types
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

B = module('container_bootstrap_test', ROOT / 'src/main/resources/bin/kura-container-bootstrap.py')
POLICY_PATH = Path(os.environ.get('KURA_KEY_POLICY_SOURCE', str(ROOT.parent / 'kura/kura/distrib/src/main/resources/unfiltered/pkg/bin/kura_key_store.py')))
P = module('container_core_policy_test', POLICY_PATH)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(value)
    path.chmod(0o600)


def envelope(key, plaintext=b'container-migration-test'):
    nonce = secrets.token_bytes(12)
    return base64.b64encode(nonce) + b'-' + base64.b64encode(AESGCM(key).encrypt(nonce, plaintext, None))


def file_state(root):
    return {str(path.relative_to(root)): (path.lstat().st_ino, path.read_bytes())
            for path in root.rglob('*') if path.is_file() and not path.is_symlink()}


class ContainerCredentials(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.home = self.base / 'home'
        self.volume = self.base / 'volume'
        self.home.mkdir(mode=0o700)
        self.volume.mkdir(mode=0o700)
        write(self.home / 'user/snapshots/snapshot_0.xml', b'<configs/>')
        write(self.home / 'user/kura_custom.properties', b'kura.snapshots.encrypt=false\n')
        write(self.home / 'user/security/cacerts.ks', b'factory-public-truststore')
        self.factory = {str(path.relative_to(self.home)): hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in self.home.rglob('*') if path.is_file()}
        self.keytool_calls = 0

    def bootstrap(self, env=None, home=None, volume=None):
        return B.Bootstrap(home or self.home, volume or self.volume, environ=env or {}, factory=self.factory, policy=P)

    def keytool(self, args, **kwargs):
        self.keytool_calls += 1
        write(Path(args[args.index('-keystore') + 1]), b'unit-tls-' + secrets.token_bytes(16))
        return types.SimpleNamespace(returncode=0)

    def prepare(self, env=None):
        return self.bootstrap(env).prepare(self.keytool)

    def test_container_loads_only_the_policy_paired_to_the_installed_package(self):
        source = b'PAIRED_POLICY_EXAMPLE = True\n'
        relative = "bin/kura_key_store.py"
        paired = json.dumps({"files": {relative: hashlib.sha256(source).hexdigest()}}).encode()
        with patch.object(B, "image_asset", side_effect=[paired, source]):
            self.assertTrue(B.load_policy(self.home).PAIRED_POLICY_EXAMPLE)
        with patch.object(B, "image_asset", side_effect=[paired, b'raise AssertionError("unpaired file was run")']):
            with self.assertRaisesRegex(RuntimeError, "differs from the Core package"):
                B.load_policy(self.home)

    def key(self):
        return (self.volume / P.KEY_PATH.lstrip('/')).read_bytes()

    def legacy(self, key, root=None, encrypted=True):
        root = root or self.volume
        write(root / B.TLS_NAME, b'original-private-tls-test')
        if encrypted:
            value = envelope(key)
            # Java Properties escaping plus continuation must still authenticate.
            split = len(value) // 2
            encoded = value[:split] + b'\\\n  ' + value[split:].replace(b'=', b'\\=')
            write(root / 'data/store.save', b'/opt/eclipse/kura/user/security/httpskeystore.ks=' + encoded + b'\n')
        return file_state(root)

    def assert_retained(self, before, root=None):
        root = root or self.volume
        for name, (inode, data) in before.items():
            path = root / name
            self.assertTrue(path.lstat().st_ino == inode and path.read_bytes() == data, name)

    def test_fresh_key_is_private_and_restart_keeps_key_tls_and_custom_configuration(self):
        self.prepare()
        self.assertEqual(len(self.key()), 32)
        self.assertEqual((self.volume / P.KEY_PATH.lstrip('/')).stat().st_mode & 0o777, 0o400)
        first = file_state(self.volume)
        self.prepare()
        self.assert_retained(first)
        self.assertEqual(self.keytool_calls, 1)
        self.assertEqual((self.home / 'user/kura_custom.properties').read_bytes(), b'kura.snapshots.encrypt=false\n')
        self.assertTrue((self.home / 'user').resolve() == (self.volume / 'user').resolve())

    def test_two_instances_have_distinct_master_and_tls_keys(self):
        self.prepare()
        home, volume = self.base / 'home2', self.base / 'volume2'
        home.mkdir(); volume.mkdir()
        self.bootstrap(home=home, volume=volume).prepare(self.keytool)
        self.assertTrue(self.key() != (volume / P.KEY_PATH.lstrip('/')).read_bytes())
        self.assertTrue((self.volume / B.TLS_NAME).read_bytes() != (volume / B.TLS_NAME).read_bytes())

    def test_custom_environment_key_and_escaped_properties_retain_original_data(self):
        key = secrets.token_bytes(16).hex().encode()
        before = self.legacy(key)
        self.prepare({'KURA_CRYPTO_SECRET_KEY': key.decode()})
        self.assertTrue(self.key() == key)
        self.assert_retained(before)
        self.assertEqual(self.keytool_calls, 0)

    def test_each_historic_key_requires_authenticated_ciphertext(self):
        for index, key in enumerate((P.CORE_DEFAULT, P.OLD_DEVELOPMENT)):
            home, volume = self.base / ('oldhome' + str(index)), self.base / ('oldvol' + str(index))
            home.mkdir(); volume.mkdir()
            before = self.legacy(key, root=volume)
            result = self.bootstrap(home=home, volume=volume).prepare(self.keytool)
            self.assertTrue((volume / P.KEY_PATH.lstrip('/')).read_bytes() == key)
            self.assertTrue(result['legacyKey'])
            self.assert_retained(before, volume)

    def test_existing_plaintext_without_key_source_is_held(self):
        before = self.legacy(P.OLD_DEVELOPMENT, encrypted=False)
        with self.assertRaises(P.Refused):
            self.prepare()
        self.assert_retained(before)
        self.assertFalse((self.volume / P.KEY_PATH.lstrip('/')).exists())

    def test_wrong_explicit_key_is_held_before_credential_or_data_publication(self):
        before = self.legacy(secrets.token_bytes(32))
        with self.assertRaises(P.Refused):
            self.prepare({'KURA_CRYPTO_SECRET_KEY': 'wrong-key-1234567'})
        self.assert_retained(before)
        self.assertFalse((self.volume / P.KEY_PATH.lstrip('/')).exists())
        self.assertTrue((self.home / 'user').is_dir() and not (self.home / 'user').is_symlink())

    def test_unknown_legacy_ciphertext_is_not_replaced(self):
        before = self.legacy(secrets.token_bytes(32))
        with self.assertRaises(P.Refused):
            self.prepare()
        self.assert_retained(before)
        self.assertFalse((self.volume / P.KEY_PATH.lstrip('/')).exists())

    def test_missing_original_tls_is_held_even_with_correct_data_key(self):
        write(self.volume / 'data/store.save', b'key=' + envelope(P.OLD_DEVELOPMENT) + b'\n')
        before = file_state(self.volume)
        with self.assertRaises(P.Refused):
            self.prepare({'KURA_CRYPTO_SECRET_KEY': P.OLD_DEVELOPMENT.decode()})
        self.assert_retained(before)
        self.assertEqual(self.keytool_calls, 0)

    def test_old_home_only_state_is_archived_and_reached_at_original_logical_path(self):
        before = self.legacy(P.OLD_DEVELOPMENT, root=self.home)
        self.prepare()
        for name, (_, data) in before.items():
            self.assertTrue((self.home / name).read_bytes() == data)
        self.assertTrue((self.home / '.container-original-user/security/httpskeystore.ks').read_bytes() == b'original-private-tls-test')

    def test_conflicting_locations_are_held_before_key_publication(self):
        self.legacy(P.OLD_DEVELOPMENT)
        write(self.home / B.TLS_NAME, b'other-private-tls-test')
        before = file_state(self.volume)
        with self.assertRaises(P.Refused):
            self.prepare()
        self.assert_retained(before)
        self.assertFalse((self.volume / P.KEY_PATH.lstrip('/')).exists())

    def test_factory_collision_with_custom_home_is_held_without_silent_data_loss(self):
        write(self.volume / 'user/kura_custom.properties', b'kura.snapshots.encrypt=false\n')
        write(self.home / 'user/kura_custom.properties', b'kura.snapshots.encrypt=true\n')
        with self.assertRaises(P.Refused):
            self.prepare()
        self.assertFalse((self.volume / P.KEY_PATH.lstrip('/')).exists())

    def test_canonical_key_conflict_and_missing_key_with_receipt_are_held(self):
        self.prepare()
        before = file_state(self.volume)
        with self.assertRaises(P.Refused):
            self.prepare({'KURA_CRYPTO_SECRET_KEY': 'different-key-123'})
        self.assert_retained(before)
        (self.volume / P.KEY_PATH.lstrip('/')).unlink()
        with self.assertRaises(P.Refused):
            self.prepare()
        self.assertFalse((self.volume / P.KEY_PATH.lstrip('/')).exists())

    def test_missing_tls_on_initialized_volume_never_regenerates_it(self):
        self.prepare()
        (self.volume / B.TLS_NAME).unlink()
        with self.assertRaises(P.Refused):
            self.prepare()
        self.assertEqual(self.keytool_calls, 1)

    def test_credential_file_precedes_jvm_and_environment_without_logging_key(self):
        key = secrets.token_bytes(32)
        before = self.legacy(key)
        credential = self.base / 'source-credentials'; credential.mkdir(mode=0o700)
        write(credential / P.CREDENTIAL, key)
        boot = self.bootstrap({'CREDENTIALS_DIRECTORY': str(credential), 'JAVA_OPTS': '-Xmx256m -D' + P.PROPERTY + '=different-key-123', 'KURA_CRYPTO_SECRET_KEY': 'env-value-123456'})
        boot.prepare(self.keytool)
        self.assertTrue(self.key() == key)
        self.assertEqual(boot.sanitized['JAVA_OPTS'], '-Xmx256m')
        self.assert_retained(before)

    def test_jvm_property_precedes_environment_and_is_removed_from_options(self):
        key = b'jvm-property-123'
        self.legacy(P.effective_key(key))
        boot = self.bootstrap({'JAVA_OPTS': '-D' + P.PROPERTY + '=' + key.decode(), 'KURA_CRYPTO_SECRET_KEY': 'other-value-1234'})
        boot.prepare(self.keytool)
        self.assertTrue(self.key() == P.effective_key(key))
        self.assertNotIn(P.PROPERTY, boot.sanitized['JAVA_OPTS'])

    def test_dynamic_conflicting_and_argument_file_key_sources_are_held(self):
        for options in ['-D' + P.PROPERTY + '=$UNRESOLVED', '@hidden-jvm-options',
                        '-D' + P.PROPERTY + '=first-key-123456 -D' + P.PROPERTY + '=other-key-123456']:
            with self.subTest(options=options), self.assertRaises(P.Refused):
                self.bootstrap({'JAVA_OPTS': options}).explicit_key()

    def test_unsafe_symlink_and_group_writable_ciphertext_are_held(self):
        self.legacy(P.OLD_DEVELOPMENT)
        data = self.volume / 'data/store.save'
        data.chmod(0o666)
        with self.assertRaises(P.Refused):
            self.prepare()
        data.chmod(0o600)
        target = self.base / 'outside'; write(target, b'unchanged')
        (self.volume / 'user/link').symlink_to(target)
        with self.assertRaises(P.Refused):
            self.prepare()
        self.assertEqual(target.read_bytes(), b'unchanged')

    def test_concurrent_instance_lock_holds_before_data_changes(self):
        self.prepare()
        before = file_state(self.volume)
        with self.bootstrap().instance_locked():
            with self.assertRaises(BlockingIOError):
                self.prepare()
        self.assert_retained(before)

    def test_image_inventory_refuses_server_private_key(self):
        write(self.home / B.TLS_NAME, b'private-test')
        with self.assertRaises(RuntimeError):
            B.inventory(self.home, self.base / 'inventory.json')
        self.assertFalse((self.base / 'inventory.json').exists())

    def test_overlay_directory_rename_fallback_verifies_complete_archive(self):
        before = self.legacy(P.OLD_DEVELOPMENT, root=self.home)
        import errno
        with patch.object(Path, 'rename', side_effect=OSError(errno.EXDEV, 'unit overlay boundary')):
            self.prepare()
        for name, (_, data) in before.items():
            self.assertTrue((self.home / name).read_bytes() == data)
        self.assertTrue((self.home / '.container-original-user/security/httpskeystore.ks').exists())

    def test_overlay_archive_accepts_trusted_versioned_home_symlink(self):
        alias = self.base / 'kura'
        alias.symlink_to(self.home, target_is_directory=True)
        import errno
        with patch.object(Path, 'rename', side_effect=OSError(errno.EXDEV, 'unit overlay boundary')):
            self.bootstrap(home=alias).prepare(self.keytool)
        self.assertTrue((alias / 'user').resolve() == (self.volume / 'user').resolve())

    def test_failed_overlay_backup_keeps_original_directory(self):
        before = file_state(self.home)
        import errno
        boot = self.bootstrap()
        with patch.object(Path, 'rename', side_effect=OSError(errno.EXDEV, 'unit overlay boundary')), patch.object(B.shutil, 'copytree', side_effect=OSError('unit disk write failure')):
            with self.assertRaises(OSError):
                boot.archive_directory(self.home / 'user', self.home / '.container-original-user')
        self.assert_retained(before, self.home)

    def test_runtime_argv_uses_private_credentials_and_original_custom_config_path(self):
        boot = self.bootstrap({'JAVA_OPTS': '-Xmx256m -D' + P.PROPERTY + '=test-key-1234567', 'KURA_DEVICE_NAME': 'Test Device'})
        boot.runtime_identity = (122, 122)
        boot.explicit_key()
        write(self.home / 'plugins/org.eclipse.equinox.launcher-1.7.100.jar', b'launcher-test')
        runtime = self.base / 'run'
        credentials = runtime / 'credentials'
        with patch.object(boot, 'setup_runtime', return_value=(credentials, runtime / 'configuration')), \
                patch.object(B.subprocess, 'run') as check, patch.object(B.os, 'execve') as execute:
            boot.exec_runtime({'credentialDirectory': str(self.volume / 'etc/kura/credentials')}, [])
        command, argv, env = execute.call_args.args
        self.assertEqual(command, '/bin/setpriv')
        options = ['/bin/setpriv', '--no-new-privs', '--bounding-set=-all', '--inh-caps=-all',
                   '--ambient-caps=-all', '--regid=122', '--reuid=122', '--clear-groups']
        self.assertEqual(argv[:len(options) + 1], [*options, '/usr/bin/java'])
        self.assertEqual(check.call_args.args[0][:len(options)], options)
        self.assertEqual(env['CREDENTIALS_DIRECTORY'], str(credentials))
        self.assertFalse(any(arg.startswith('-Dosgi.console') for arg in argv))
        self.assertNotIn('KURA_CRYPTO_SECRET_KEY', env)
        self.assertNotIn(P.PROPERTY, ' '.join(argv))
        self.assertIn('-Dkura.custom.configuration=file:' + str(self.home / 'user/kura_custom.properties'), argv)
        self.assertIn('-Dkura.home=' + str(self.home), argv)
        self.assertIn('-Dkura.device.name=Test Device', argv)
        self.assertEqual(env['PERSISTENT_DIR'], str(self.volume))

    def test_unreadable_equinox_template_preserves_existing_configuration(self):
        boot = self.bootstrap()
        boot.runtime_identity = (os.getuid(), os.getgid())
        runtime = self.base / 'run'
        canonical = self.base / 'canonical'
        write(canonical / P.CREDENTIAL, secrets.token_bytes(32))
        existing = runtime / 'configuration/config.ini'
        write(existing, b'previous configuration')
        inode = existing.stat().st_ino
        (self.home / 'framework/config.ini').mkdir(parents=True)
        with patch.object(B, 'RUNTIME', runtime), patch.object(B.subprocess, 'run') as loader:
            with self.assertRaises(IsADirectoryError):
                boot.setup_runtime(canonical)
        loader.assert_not_called()
        self.assertEqual(existing.read_bytes(), b'previous configuration')
        self.assertEqual(existing.stat().st_ino, inode)
        self.assertEqual(list(runtime.glob('.kura-stage-*')), [])

    def test_link_maintenance_needs_the_existing_stopped_volume_and_drops_privileges(self):
        boot = self.bootstrap({'JAVA_TOOL_OPTIONS': '-Dtest=true'})
        boot.runtime_identity = (122, 122)
        info = self.volume.stat()
        root_id = f"{info.st_dev}:{info.st_ino}"
        configured = str(self.home / "data/business.p12")
        args = [root_id, "business", configured, "a" * 64]
        with self.assertRaises(P.Refused):
            boot.separate_keystore_links(*args)
        self.assertEqual(list(self.volume.iterdir()), [])
        self.prepare()
        before = file_state(self.volume)
        write(self.home / "plugins/4s/org.eclipse.kura.core.keystore-test.jar", b"provider")
        with patch.object(B.subprocess, "run") as worker:
            with self.assertRaises(P.Refused):
                boot.separate_keystore_links("0:0", *args[1:])
            with boot.instance_locked(), self.assertRaises(BlockingIOError):
                boot.separate_keystore_links(*args)
            worker.assert_not_called()
            boot.separate_keystore_links(*args)
        argv = worker.call_args.args[0]
        self.assertIn("--no-new-privs", argv)
        self.assertIn("--reuid=122", argv)
        self.assertIn("--bounding-set=-all", argv)
        self.assertEqual(argv[-5:], [str(self.volume), "business", configured,
                                    str(self.volume / "data/business.p12"), "a" * 64])
        self.assertEqual(worker.call_args.kwargs["env"], B.ROOT_TOOL_ENV)
        self.assert_retained(before)

    def test_runtime_preflight_refuses_hardlinked_state_before_transfer(self):
        boot = self.bootstrap()
        boot.runtime_identity = (122, 122)
        write(self.volume / 'data/original', b'retained')
        os.link(self.volume / 'data/original', self.volume / 'data/alias')
        with self.assertRaisesRegex(P.Refused, 'unreviewed type'):
            boot.runtime_state_entries([self.volume / 'data'])

    def test_privileged_keytool_does_not_inherit_jvm_option_sources(self):
        boot = self.bootstrap({'JAVA_TOOL_OPTIONS': '-Xmx64m', 'JDK_JAVA_OPTIONS': '-Dexample=true'})
        with patch.dict(os.environ, {'JAVA_TOOL_OPTIONS': '-Xmx64m', 'JDK_JAVA_OPTIONS': '-Dexample=true'}):
            with patch.object(self, 'keytool', wraps=self.keytool) as tool:
                boot.prepare(tool)
        command = tool.call_args.args[0]
        self.assertEqual(command[0], '/usr/bin/keytool')
        self.assertFalse(set(tool.call_args.kwargs['env']) & set(B.OPTION_NAMES))


if __name__ == '__main__':
    unittest.main()
