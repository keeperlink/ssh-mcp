"""Offline tests of the live-source clone tool; no real Docker operations."""
from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, call, patch

HELPER = Path(__file__).resolve().parents[2] / "ops" / "preview"
sys.path.insert(0, str(HELPER))
try:
    import preview
finally:
    sys.path.remove(str(HELPER))

ORIGINAL_ID = "a" * 64
DEV_ID = "b" * 64
TARGET = "/usr/local/lib/python3.14/site-packages/app"
VERSION_FILE = Path("/tmp/ssh-mcp-preview-synthetic/version")


def original(*, running=True):
    return {
        "Id": ORIGINAL_ID, "Image": "sha256:" + "c" * 64,
        "State": {"Running": running, "Status": "running" if running else "exited"},
        "Config": {
            "Hostname": ORIGINAL_ID[:12], "Image": "demo:latest",
            "User": "10001:10001", "Env": ["MCP_ENVIRONMENT=production", "PYTHONPATH=/unchanged"],
            "Cmd": ["python", "-m", "app"], "WorkingDir": "/var/lib/ssh-mcp",
            "Healthcheck": {"Test": ["CMD", "health"]}, "Labels": {
                "com.docker.compose.project": "demo", "com.docker.compose.service": "demo",
                "org.example.test": "yes",
            },
            "StopTimeout": 45, "Volumes": {"/anonymous": {}},
        },
        "HostConfig": {
            "Binds": ["demo-state:/var/lib/ssh-mcp:rw", "/extra:/extra:ro"],
            "Mounts": [
                {"Type": "bind", "Source": "/synthetic/config", "Target": "/etc/ssh-mcp/service.json",
                 "ReadOnly": True, "BindOptions": {"Propagation": "rprivate"}},
                {"Type": "volume", "Target": "/typed", "VolumeOptions": {"NoCopy": True}},
            ],
            "NetworkMode": "demo-ingress",
            "PortBindings": {"8000/tcp": [{"HostIp": "192.0.2.10", "HostPort": "8014"}]},
            "Tmpfs": {"/run/ssh-mcp": "rw,mode=0700"},
            "ReadonlyRootfs": True, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"],
            "PidsLimit": 128, "Memory": 536870912, "NanoCpus": 1000000000,
            "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
            "LogConfig": {"Type": "json-file", "Config": {"max-size": "20m"}},
            "ContainerIDFile": "/original.cid",
        },
        "NetworkSettings": {"Networks": {
            "demo-ingress": {"Aliases": ["existing", "demo", "demo"], "NetworkID": "network-id",
                             "EndpointID": "endpoint-id", "IPAddress": "172.18.0.2",
                             "MacAddress": "02:42:ac:12:00:02", "DNSNames": ["old-id"],
                             "GwPriority": 1},
            "demo-transit": {"Aliases": None, "IPAMConfig": {"IPv4Address": "192.0.2.10"}},
            "additional-network": {"DriverOpts": {"example": "value"}},
        }},
        "Mounts": [
            {"Type": "bind", "Destination": "/etc/ssh-mcp/service.json", "RW": False},
            {"Type": "bind", "Destination": "/extra", "RW": False},
            {"Type": "volume", "Destination": "/var/lib/ssh-mcp", "Name": "demo-state", "RW": True},
            {"Type": "volume", "Destination": "/typed", "Name": "typed-volume", "RW": True},
            {"Type": "volume", "Destination": "/anonymous", "Name": "existing-anonymous", "RW": False},
        ],
    }


def fixture(*, original_id=ORIGINAL_ID, running=True):
    return {"Id": DEV_ID, "State": {"Running": running, "Status": "running" if running else "created"},
            "Config": {"Labels": {preview.LABEL: original_id}},
            "Mounts": [{"Type": "bind", "Source": str(preview.SOURCE), "Destination": TARGET, "RW": False}]}


class PreviewTests(unittest.TestCase):
    def test_clone_preserves_config_and_resources_without_mutating_original(self):
        item = original()
        before = deepcopy(item)
        config = preview.clone_config(item, "demo", TARGET, VERSION_FILE)
        self.assertEqual(item, before)
        self.assertEqual(config["Image"], item["Image"])
        self.assertNotIn("Hostname", config)
        self.assertEqual(config["Labels"], {"org.example.test": "yes", preview.LABEL: ORIGINAL_ID})
        for key in ("Env", "Cmd", "User", "WorkingDir", "Healthcheck", "StopTimeout", "Volumes"):
            self.assertEqual(config[key], item["Config"][key])
        host = config["HostConfig"]
        for key in ("PortBindings", "NetworkMode", "Tmpfs", "ReadonlyRootfs", "CapDrop", "SecurityOpt",
                    "PidsLimit", "Memory", "NanoCpus", "LogConfig"):
            self.assertEqual(host[key], item["HostConfig"][key])
        self.assertEqual(host["RestartPolicy"]["Name"], "no")
        self.assertEqual(host["ContainerIDFile"], "")
        self.assertEqual(host["Binds"], item["HostConfig"]["Binds"])
        self.assertEqual(host["Mounts"][0], item["HostConfig"]["Mounts"][0])
        self.assertEqual(host["Mounts"][1]["Source"], "typed-volume")
        self.assertEqual(host["Mounts"][2], {
            "Type": "volume", "Source": "existing-anonymous", "Target": "/anonymous",
            "ReadOnly": True, "VolumeOptions": {"NoCopy": True}})
        self.assertEqual(host["Mounts"][3], {
            "Type": "bind", "Source": str(preview.SOURCE), "Target": TARGET, "ReadOnly": True})
        self.assertEqual(host["Mounts"][4], {
            "Type": "bind", "Source": str(VERSION_FILE), "Target": preview.VERSION, "ReadOnly": True})
        self.assertEqual(config["NetworkingConfig"]["EndpointsConfig"], {
            "demo-ingress": {"Aliases": ["existing", "demo"], "GwPriority": 1},
            "demo-transit": {"Aliases": ["demo"], "IPAMConfig": {"IPv4Address": "192.0.2.10"}},
            "additional-network": {"Aliases": ["demo"], "DriverOpts": {"example": "value"}},
        })
        self.assertNotIn("Id", config)
        self.assertNotIn("State", config)

    def test_preserve_explicit_hostname_and_anonymous_bind_identity(self):
        item = original()
        item["Config"]["Hostname"] = "custom-host"
        item["HostConfig"]["Binds"].append("/anonymous")
        config = preview.clone_config(item, "demo", TARGET, VERSION_FILE)
        self.assertEqual(config["Hostname"], "custom-host")
        self.assertIn("existing-anonymous:/anonymous:ro", config["HostConfig"]["Binds"])
        self.assertFalse(any(m["Target"] == "/anonymous" for m in config["HostConfig"]["Mounts"]))

    def test_fail_closed_on_unsupported_or_conflicting_mounts(self):
        for key, value in (("AutoRemove", True), ("VolumesFrom", ["other"])):
            item = original()
            item["HostConfig"][key] = value
            with self.assertRaises(RuntimeError):
                preview.clone_config(item, "demo", TARGET, VERSION_FILE)
        with self.assertRaisesRegex(RuntimeError, "already a mount"):
            preview.clone_config(original(), "demo", "/extra", VERSION_FILE)

    def test_default_network_does_not_get_unsupported_alias(self):
        item = original()
        item["NetworkSettings"]["Networks"] = {"bridge": {"IPAddress": "192.0.2.20"}}
        config = preview.clone_config(item, "demo", TARGET, VERSION_FILE)
        self.assertEqual(config["NetworkingConfig"]["EndpointsConfig"], {"bridge": {}})

    def test_commit_version_uses_checked_out_head(self):
        with patch.object(preview.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "abc1234\n"
            self.assertEqual(preview.commit_version(), "abc1234")
            self.assertEqual(run.call_args.args[0],
                             ["git", "-C", str(preview.SOURCE.parent), "rev-parse", "--short=7", "HEAD"])
            run.return_value.stdout = "not-a-commit"
            with self.assertRaisesRegex(RuntimeError, "Cannot determine checkout commit"):
                preview.commit_version()

    def test_version_file_lifecycle_and_in_place_update(self):
        with patch.object(preview, "commit_version", return_value="abc1234"):
            path = preview.new_version_file()
        try:
            self.assertEqual(path.read_text(), "abc1234\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            inode = path.stat().st_ino
            item = fixture()
            item["Mounts"].append({"Type": "bind", "Source": str(path),
                                   "Destination": preview.VERSION, "RW": False})
            self.assertEqual(preview.mounted_version_file(item), path)
            with patch.object(preview, "commit_version", return_value="def5678"):
                preview.write_version(path)
            self.assertEqual(path.stat().st_ino, inode)
            self.assertEqual(path.read_text(), "def5678\n")
            item["Mounts"][-1]["RW"] = True
            with self.assertRaisesRegex(RuntimeError, "Unexpected preview version mount"):
                preview.mounted_version_file(item)
        finally:
            preview.remove_version_file(path)
        self.assertFalse(path.parent.exists())

    def test_engine_connection_uses_only_local_unix_socket(self):
        connection = preview.EngineConnection()
        with patch.object(preview.socket, "socket") as factory:
            connection.connect()
            factory.assert_called_once_with(preview.socket.AF_UNIX, preview.socket.SOCK_STREAM)
            factory.return_value.connect.assert_called_once_with(preview.SOCKET)
            factory.return_value.settimeout.assert_called_once_with(60)
            connection.close()

    def test_create_uses_local_versioned_engine_api(self):
        with patch.object(preview, "docker", return_value="1.56") as docker, \
             patch.object(preview, "EngineConnection") as factory:
            connection = factory.return_value
            response = connection.getresponse.return_value
            response.status = 201
            response.read.return_value = json.dumps({"Id": DEV_ID}).encode()
            config = {"Image": "sha256:synthetic"}
            self.assertEqual(preview.create("demo-dev", config), DEV_ID)
            docker.assert_called_once_with("version", "--format", "{{.Server.APIVersion}}")
            request = connection.request.call_args
            self.assertEqual(request.args, ("POST", "/v1.56/containers/create?name=demo-dev"))
            self.assertEqual(json.loads(request.kwargs["body"]), config)
            self.assertEqual(request.kwargs["headers"], {"Content-Type": "application/json"})
            connection.close.assert_called_once_with()

    def test_engine_failure_does_not_echo_private_response(self):
        with patch.object(preview, "docker", return_value="1.56"), \
             patch.object(preview, "EngineConnection") as factory:
            connection = factory.return_value
            response = connection.getresponse.return_value
            response.status = 400
            response.read.return_value = b"private-config"
            with self.assertRaisesRegex(RuntimeError, r"^Docker create failed \(HTTP 400\)$"):
                preview.create("demo-dev", {})
            response.read.assert_not_called()
            connection.close.assert_called_once_with()

    def test_discover_package_without_importing_application(self):
        with patch.object(preview, "docker", return_value=TARGET) as docker:
            self.assertEqual(preview.package_path(ORIGINAL_ID), TARGET)
            self.assertEqual(docker.call_args.args[:4], ("exec", ORIGINAL_ID, "python", "-c"))
            self.assertIn("find_spec('app')", docker.call_args.args[4])
        for invalid in ("app", "/", "/etc", "/tmp/app\n/other/app"):
            with patch.object(preview, "docker", return_value=invalid):
                with self.assertRaisesRegex(RuntimeError, "Cannot locate"):
                    preview.package_path(ORIGINAL_ID)

    def test_create_precedes_stop_and_start(self):
        item = original()
        with patch.object(preview, "inspect", return_value=item), \
             patch.object(preview, "fixture_exists", return_value=False), \
             patch.object(preview, "package_path", return_value=TARGET), \
             patch.object(preview, "new_version_file", return_value=VERSION_FILE), \
             patch.object(preview, "remove_version_file") as remove, \
             patch.object(preview, "docker") as docker, \
             patch.object(preview, "create", return_value=DEV_ID) as create:
            events = Mock()
            events.attach_mock(docker, "docker")
            events.attach_mock(create, "create")
            preview.operate("start", "demo")
            self.assertEqual(events.mock_calls, [
                call.create("demo-dev", preview.clone_config(item, "demo", TARGET, VERSION_FILE)),
                call.docker("stop", ORIGINAL_ID), call.docker("start", DEV_ID)])
            create.side_effect = RuntimeError("Create failed")
            docker.reset_mock()
            with self.assertRaisesRegex(RuntimeError, "Create failed"):
                preview.operate("start", "demo")
            docker.assert_not_called()
            remove.assert_called_once_with(VERSION_FILE)

    def test_start_refuses_existing_fixture_or_stopped_original(self):
        for item, exists in ((original(), True), (original(running=False), False)):
            with self.subTest(exists=exists), \
                 patch.object(preview, "inspect", return_value=item), \
                 patch.object(preview, "fixture_exists", return_value=exists), \
                 patch.object(preview, "docker") as docker, \
                 patch.object(preview, "create") as create:
                with self.assertRaisesRegex(RuntimeError, "Need running original"):
                    preview.operate("start", "demo")
                create.assert_not_called()
                docker.assert_not_called()

    def test_cli_requires_no_hostname_or_environment_argument(self):
        with patch.object(sys, "argv", ["preview.py", "start", "--container", "demo"]), \
             patch.object(preview.os, "geteuid", return_value=1000), \
             patch.object(preview, "operate") as operate:
            self.assertEqual(preview.main(), 0)
            operate.assert_called_once_with("start", "demo")

    def test_stop_and_restart(self):
        for action, expected in (
            ("restart", [call("restart", DEV_ID)]),
            ("stop", [call("stop", DEV_ID), call("rm", DEV_ID), call("start", ORIGINAL_ID)]),
        ):
            with self.subTest(action=action), \
                 patch.object(preview, "inspect", side_effect=[original(running=False), fixture()]), \
                 patch.object(preview, "fixture_exists", return_value=True), \
                 patch.object(preview, "mounted_version_file", return_value=VERSION_FILE), \
                 patch.object(Path, "is_file", return_value=True), \
                 patch.object(preview, "write_version") as write, \
                 patch.object(preview, "remove_version_file") as remove, \
                 patch.object(preview, "docker") as docker:
                preview.operate(action, "demo")
                self.assertEqual(docker.mock_calls, expected)
                if action == "restart":
                    write.assert_called_once_with(VERSION_FILE)
                    remove.assert_not_called()
                else:
                    remove.assert_called_once_with(VERSION_FILE)
                    write.assert_not_called()

    def test_stop_can_remove_created_fixture_after_failed_switch(self):
        for is_running in (True, False):
            with patch.object(preview, "inspect", side_effect=[
                    original(running=is_running), fixture(running=False)]), \
                 patch.object(preview, "fixture_exists", return_value=True), \
                 patch.object(preview, "docker") as docker:
                preview.operate("stop", "demo")
                expected = [call("rm", DEV_ID)]
                if not is_running:
                    expected.append(call("start", ORIGINAL_ID))
                self.assertEqual(docker.mock_calls, expected)

    def test_refuse_wrong_fixture_or_running_original(self):
        for action, item, dev in (("stop", original(), fixture()),
                                  ("stop", original(running=False), fixture(original_id="other")),
                                  ("restart", original(), fixture(running=False))):
            with patch.object(preview, "inspect", side_effect=[item, dev]), \
                 patch.object(preview, "fixture_exists", return_value=True), \
                 patch.object(preview, "docker") as docker:
                with self.assertRaises(RuntimeError):
                    preview.operate(action, "demo")
                docker.assert_not_called()

    def test_status(self):
        with patch.object(preview, "inspect", return_value=original()), \
             patch.object(preview, "fixture_exists", return_value=False), redirect_stdout(StringIO()) as out:
            preview.operate("status", "demo")
        self.assertIn("demo: running", out.getvalue())
        self.assertIn("demo-dev: absent", out.getvalue())


if __name__ == "__main__":
    unittest.main()
