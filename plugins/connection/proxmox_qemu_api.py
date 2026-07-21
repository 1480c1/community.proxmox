# Copyright (c) 2025 Ian Williams (@aph3rson)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations
import shlex

DOCUMENTATION = r"""
---
name: proxmox_qemu_api
short_description: Connect to QEMU VMs via the Proxmox guest agent API
description:
  - Execute commands and transfer files through the Proxmox VE QEMU Guest Agent API.
  - Does not require SSH or network connectivity to the VM.
  - Requires the QEMU Guest Agent (C(qemu-guest-agent)) to be installed and running inside the target VM.
  - Talks directly to the Proxmox REST API using C(proxmoxer), avoiding the overhead and limitations
    of shelling out to C(qm guest exec) over SSH.
  - Supports Linux and Windows guests.
author:
  - Ian Williams (@aph3rson)
version_added: "2.0.0"
requirements:
  - proxmoxer >= 2.3.0
  - requests
options:
  api_host:
    description: Proxmox VE API hostname or IP address.
    required: true
    type: str
    vars:
      - name: proxmox_api_host
    env:
      - name: PROXMOX_HOST
  api_port:
    description: Proxmox VE API port.
    default: 8006
    type: int
    vars:
      - name: proxmox_api_port
    env:
      - name: PROXMOX_PORT
  api_user:
    description:
      - Proxmox VE API user (for example V(root@pam)).
      - Used with O(api_password) to obtain an authentication ticket.
      - Alternatively used with O(api_token_id) and O(api_token_secret) for token-based authentication.
    required: true
    type: str
    vars:
      - name: proxmox_api_user
    env:
      - name: PROXMOX_USER
  api_password:
    description:
      - Password for O(api_user).
      - Required when O(api_user) is set.
    type: str
    vars:
      - name: proxmox_api_password
    env:
      - name: PROXMOX_PASSWORD
  api_token_id:
    description:
      - API token ID (for example V(token_name)).
      - Used with O(api_user) and O(api_token_secret).
    type: str
    vars:
      - name: proxmox_api_token_id
    env:
      - name: PROXMOX_TOKEN_ID
  api_token_secret:
    description:
      - API token secret UUID.
      - Required when O(api_token_id) is set.
    type: str
    vars:
      - name: proxmox_api_token_secret
    env:
      - name: PROXMOX_TOKEN_SECRET
  node:
    description: Proxmox node name where the VM resides.
    required: true
    type: str
    vars:
      - name: proxmox_node
    env:
      - name: PROXMOX_NODE
  vmid:
    description: Target QEMU VM ID.
    required: true
    type: int
    vars:
      - name: proxmox_vmid
    env:
      - name: PROXMOX_VMID
  validate_certs:
    description: Validate PVE API TLS certificates.
    default: true
    type: bool
    vars:
      - name: proxmox_validate_certs
    env:
      - name: PROXMOX_VERIFY_SSL
  guest_os:
    description:
      - Guest operating system family.
      - When set to V(auto), the plugin queries the QEMU guest agent (C(get-osinfo))
        during connection to detect Windows guests.
      - Set explicitly to avoid the detection API call or when the API user lacks
        permission for C(VM.GuestAgent.Audit).
    choices: [auto, posix, windows]
    default: auto
    type: str
    vars:
      - name: proxmox_guest_os
  guest_shell:
    description:
      - Shell family to use when invoking commands on the guest.
      - V(auto) selects C(powershell) on detected Windows guests when O(guest_os=windows)
        or when C(ansible_shell_type) is C(powershell), otherwise V(sh).
      - Ignored when O(guest_os=posix).
    choices: [auto, sh, powershell, cmd]
    default: auto
    type: str
    vars:
      - name: proxmox_guest_shell
  remote_tmp:
    description:
      - Temporary directory on the guest for staging chunked file transfers.
      - Must be writable by the guest agent process (root on Linux, SYSTEM on Windows).
      - Only used when transferring files larger than 45000 bytes.
      - If not set, V(/tmp) is used on POSIX guests and V(C:/Windows/Temp) on Windows guests.
    type: str
    vars:
      - name: proxmox_remote_tmp
  executable:
    description:
      - Shell executable for command execution on the guest.
      - If not set, V(/bin/sh) is used on POSIX guests and V(powershell.exe) on Windows guests.
    type: str
    vars:
      - name: ansible_executable
  connect_timeout:
    description:
      - Maximum number of seconds to wait for the guest agent to become responsive.
      - The plugin polls the agent every 5 seconds during connection.
    default: 60
    type: int
    vars:
      - name: proxmox_connect_timeout
notes:
  - The API user or token requires guest agent privileges on the target VM.
    On PVE 8, this is C(VM.Monitor). On PVE 9+, C(VM.Monitor) was replaced with
    fine-grained privileges -- C(VM.GuestAgent.Unrestricted) covers command execution,
    C(VM.GuestAgent.FileRead) and C(VM.GuestAgent.FileWrite) cover file transfers.
    Alternatively, C(VM.GuestAgent.Unrestricted) alone grants access to all guest agent operations.
  - This plugin requires the QEMU Guest Agent to be installed and running inside the VM.
    If the agent is not responsive, the connection will fail after O(connect_timeout) seconds.
  - File transfers use the PVE guest agent file-read/file-write API, which has a per-call
    size limit of approximately 45000 bytes. Files larger than this are automatically
    split into chunks.
  - "POSIX guest requirements: C(qemu-guest-agent) must be running."
  - "Windows guest requirements: C(QEMU Guest Agent) must be running and PowerShell must be available."
  - Windows detection uses the C(get-osinfo) guest agent command and requires
    C(VM.GuestAgent.Audit) or C(VM.GuestAgent.Unrestricted).
  - Works with the C(community.proxmox.proxmox) inventory plugin. Set
    C(ansible_connection=community.proxmox.proxmox_qemu_api) on discovered hosts.
"""

EXAMPLES = r"""
- name: Static inventory example (Linux guest)
  # inventory.yml
  # all:
  #   hosts:
  #     my-vm:
  #       ansible_connection: community.proxmox.proxmox_qemu_api
  #       proxmox_vmid: 100
  #       ansible_host: my-vm.example.com
  #   vars:
  #     proxmox_api_host: pve-1.example.com
  #     proxmox_api_port: 8006
  #     proxmox_api_token_id: automation@pve!ansible
  #     proxmox_api_token_secret: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  #     proxmox_node: pve-1
  hosts: my-vm
  gather_facts: true
  tasks:
    - name: Install a package
      ansible.builtin.apt:
        name: curl
        state: present

    - name: Copy a configuration file
      ansible.builtin.copy:
        src: app.conf
        dest: /etc/app/app.conf

    - name: Run a command
      ansible.builtin.command:
        cmd: systemctl restart app

- name: Static inventory example (Windows guest)
  # inventory.yml
  # all:
  #   hosts:
  #     win-vm:
  #       ansible_connection: community.proxmox.proxmox_qemu_api
  #       ansible_shell_type: powershell
  #       proxmox_vmid: 101
  #       ansible_host: win-vm.example.com
  #   vars:
  #     proxmox_api_host: pve-1.example.com
  #     proxmox_api_port: 8006
  #     proxmox_api_token_id: automation@pve!ansible
  #     proxmox_api_token_secret: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  #     proxmox_node: pve-1
  hosts: win-vm
  gather_facts: true
  tasks:
    - name: Install a Windows feature
      ansible.windows.win_feature:
        name: Web-Server
        state: present
"""

import base64
import logging
import time

from ansible.errors import AnsibleConnectionFailure, AnsibleError
from ansible.plugins.connection import ConnectionBase
from ansible.utils.display import Display
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.community.proxmox.plugins.module_utils.proxmox import HAS_PROXMOXER

if HAS_PROXMOXER:
    from proxmoxer import ProxmoxAPI

display = Display()


class _DisplayHandler(logging.Handler):
    """Route Python logging to Ansible Display."""

    _level_map = {
        logging.DEBUG: display.vvvv,
        logging.INFO: display.vvv,
        logging.WARNING: display.warning,
    }

    def emit(self, record):
        fn = self._level_map.get(record.levelno, display.warning)
        fn(self.format(record))


# Wire urllib3/requests logging through Display instead of stderr.
_handler = _DisplayHandler()
_handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
for _name in ("urllib3", "requests", "py.warnings"):
    _logger = logging.getLogger(_name)
    _logger.handlers.clear()
    _logger.addHandler(_handler)
    _logger.propagate = False

# PVE file-write content limit is 61440 bytes.
# base64 expands 3:4, so 45000 raw bytes -> 60000 base64 chars, safely under limit.
# TODO: Increase once Proxmox raises the QEMU guest agent file-write size limit.
# https://forum.proxmox.com/threads/maximum-file-upload-size-for-qemu-agent-file-write.166200/
FILE_WRITE_CHUNK = 45000
FILE_WRITE_RETRIES = 5


class Connection(ConnectionBase):
    """Connection plugin that uses the Proxmox QEMU Guest Agent API."""

    transport = "community.proxmox.proxmox_qemu_api"
    has_pipelining = False
    has_tty = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._connected = False
        self._proxmox = None
        self._is_windows_guest = None
        logging.captureWarnings(True)

    def _get_proxmox(self):
        if self._proxmox is not None:
            return self._proxmox

        if not HAS_PROXMOXER:
            msg = "This connection plugin requires the 'proxmoxer' library"
            raise AnsibleError(msg) from None

        host = self.get_option("api_host")
        port = self.get_option("api_port")
        verify_ssl = self.get_option("validate_certs")
        token_id = self.get_option("api_token_id")
        token_secret = self.get_option("api_token_secret")
        user = self.get_option("api_user")
        password = self.get_option("api_password")

        if user and token_id and token_secret:
            self._proxmox = ProxmoxAPI(
                host,
                port=port,
                user=user,
                token_name=token_id,
                token_value=token_secret,
                verify_ssl=verify_ssl,
            )
        elif user and password:
            self._proxmox = ProxmoxAPI(
                host,
                port=port,
                user=user,
                password=password,
                verify_ssl=verify_ssl,
            )
        else:
            raise AnsibleConnectionFailure(
                "No authentication configured. Provide api_user + api_token_id + api_token_secret, or api_user + api_password."
            )

        return self._proxmox

    def _agent(self):
        proxmox = self._get_proxmox()
        node = self.get_option("node")
        vmid = self.get_option("vmid")
        return proxmox.nodes(node).qemu(vmid).agent

    def _detect_guest_os(self):
        """Detect whether the guest is Windows via get-osinfo."""
        guest_os_option = self.get_option("guest_os")
        if guest_os_option == "windows":
            return True
        if guest_os_option == "posix":
            return False

        result = self._agent()("get-osinfo").get()
        os_info = result.get("result", {})
        os_id = os_info.get("id", "").lower()
        return os_id == "mswindows"

    def _is_windows(self):
        if self._is_windows_guest is None:
            self._is_windows_guest = self._detect_guest_os()
            display.vvv(
                f"Guest OS on VM {self.get_option('vmid')} detected as "
                f"{'Windows' if self._is_windows_guest else 'POSIX'}"
            )
        return self._is_windows_guest

    def _get_remote_tmp(self):
        remote_tmp = self.get_option("remote_tmp")
        if remote_tmp:
            return remote_tmp
        if self._is_windows():
            return r"C:\Windows\Temp"
        return "/tmp"

    def _join_remote_path(self, *parts):
        if self._is_windows():
            return "\\".join(p.rstrip("\\") for p in parts)
        return "/".join(p.rstrip("/") for p in parts)

    def _get_shell_config(self):
        """Return (shell_executable, shell_argument) for exec_command."""
        guest_shell = self.get_option("guest_shell")
        executable = self.get_option("executable")

        shell_family = None
        if guest_shell != "auto":
            shell_family = guest_shell
        elif getattr(self._shell, "SHELL_FAMILY", None) == "powershell" or self._is_windows():
            shell_family = "powershell"
        else:
            shell_family = "sh"

        if shell_family == "powershell":
            return executable or "powershell.exe", "-Command"
        if shell_family == "cmd":
            return executable or "cmd.exe", "/c"
        return executable or "/bin/sh", "-c"

    def _connect(self):
        if self._connected:
            return self
        super()._connect()

        timeout = self.get_option("connect_timeout")
        interval = 5
        attempts = max(timeout // interval, 1)

        for attempt in range(attempts):
            try:
                self._agent().ping.post()
                self._connected = True
                display.vvv(f"QEMU guest agent responsive on VM {self.get_option('vmid')}")
                break
            except Exception as e:
                if attempt < attempts - 1:
                    display.vvv(
                        f"Guest agent not ready on VM {self.get_option('vmid')}, "
                        f"retrying in {interval}s ({attempt + 1}/{attempts}): {e}"
                    )
                    time.sleep(interval)
                else:
                    raise AnsibleConnectionFailure(
                        f"QEMU guest agent is not responding on VM {self.get_option('vmid')} "
                        f"after {timeout}s. Is qemu-guest-agent installed and running?"
                    ) from None

        # Best-effort OS detection once the agent responds. Detection failures are
        # logged and treated as POSIX so the connection can still proceed.
        try:
            self._is_windows()
        except Exception as exc:
            display.vvv(f"Guest OS detection failed on VM {self.get_option('vmid')}, assuming POSIX: {exc}")
            self._is_windows_guest = False

        return self

    def exec_command(self, cmd, in_data=None, sudoable=True):
        super().exec_command(cmd, in_data=in_data, sudoable=sudoable)
        self._connect()

        shell, shell_arg = self._get_shell_config()
        display.vvv(f"EXEC via guest agent: {cmd}")

        try:
            data = self._agent().exec.post(command=[shell, shell_arg, cmd])
        except Exception as exc:
            raise AnsibleConnectionFailure(f"Failed to execute command on VM {self.get_option('vmid')}: {exc}") from exc

        pid = data["pid"]
        try:
            status = self._poll_exec_status(pid)
        except Exception as exc:
            raise AnsibleConnectionFailure(
                f"Failed to poll command status on VM {self.get_option('vmid')}: {exc}"
            ) from exc

        rc = status.get("exitcode", -1)
        stdout = status.get("out-data", "")
        stderr = status.get("err-data", "")
        display.vvv(
            f"EXEC result on VM {self.get_option('vmid')}: rc={rc}, stdout={len(stdout)} bytes, stderr={len(stderr)} bytes, peek[stdout]={stdout[:100]!r}, peek[stderr]={stderr[:100]!r}"
        )
        stdout = to_bytes(stdout)
        stderr = to_bytes(stderr)
        return rc, stdout, stderr

    def _poll_exec_status(self, pid):
        while True:
            time.sleep(0.5)
            status = self._agent()("exec-status").get(pid=pid)
            if status.get("exited"):
                return status

    def _file_write(self, guest_path, data_bytes):
        encoded = base64.b64encode(data_bytes).decode("ascii")
        for attempt in range(FILE_WRITE_RETRIES + 1):
            try:
                self._agent()("file-write").post(file=guest_path, content=encoded, encode=0)
                return
            except Exception:
                if attempt < FILE_WRITE_RETRIES:
                    time.sleep(5)
                else:
                    raise AnsibleConnectionFailure(
                        f"Failed to write file {guest_path} on VM {self.get_option('vmid')} "
                        f"after {FILE_WRITE_RETRIES + 1} attempts"
                    ) from None

    def put_file(self, in_path, out_path):
        super().put_file(in_path, out_path)
        self._connect()
        display.vvv(f"PUT {in_path} -> {out_path} via guest agent")

        with open(in_path, "rb") as f:
            raw = f.read()

        if len(raw) <= FILE_WRITE_CHUNK:
            self._file_write(out_path, raw)
            return

        self._put_file_chunked(raw, out_path)

    def _put_file_chunked(self, raw, out_path):
        remote_tmp = self._get_remote_tmp()
        parts = []
        for i in range(0, len(raw), FILE_WRITE_CHUNK):
            part_path = self._join_remote_path(remote_tmp, f".ansible_part_{i:06d}")
            parts.append(part_path)
            self._file_write(part_path, raw[i : i + FILE_WRITE_CHUNK])

        if self._is_windows():
            rc, dummy_stdout, err = self._assemble_file_windows(parts, out_path)
        else:
            rc, dummy_stdout, err = self._assemble_file_posix(parts, out_path)

        if rc != 0:
            raise AnsibleConnectionFailure(f"Failed to assemble chunked file on VM {self.get_option('vmid')}: {err}")

    def _assemble_file_posix(self, parts, out_path):
        cat_cmd = "cat " + " ".join(parts) + f" > {out_path} && rm -f " + " ".join(parts)
        return self.exec_command(cat_cmd)

    def _assemble_file_windows(self, parts, out_path):
        script = f"""$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$null = New-Item -Path '{out_path}' -ItemType File -Force
Get-Content -Raw {", ".join(shlex.quote(part) for part in parts)} | Set-Content -NoNewline '{out_path}'
$null = Remove-Item -Force {", ".join(shlex.quote(part) for part in parts)}
"""
        # script_path = self._join_remote_path(remote_tmp, ".ansible_assemble.ps1")
        encoded_script = base64.b64encode(script.encode("utf-16-le")).decode()
        try:
            return self.exec_command(
                f"PowerShell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand {encoded_script}"
            )
        finally:
            pass

    def _file_read(self, guest_path, offset=0, count=None):
        """Read a file from the guest via file-read API.

        PVE encodes raw file bytes as JSON unicode escapes (\\u00XX),
        which json.loads turns into a Python str with code points 0x00-0xFF.
        latin-1 is the exact inverse: U+00NN -> byte 0xNN, preserving binary content.
        """
        kwargs = {"file": guest_path, "offset": offset}
        if count is not None:
            kwargs["count"] = count
        result = self._agent()("file-read").get(**kwargs)
        content = result.get("content", "")
        truncated = result.get("truncated", False)
        return content.encode("latin-1"), truncated

    def fetch_file(self, in_path, out_path):
        super().fetch_file(in_path, out_path)
        self._connect()
        display.vvv(f"FETCH {in_path} -> {out_path} via guest agent")

        try:
            with open(out_path, "wb") as f:
                offset = 0
                while True:
                    chunk, truncated = self._file_read(in_path, offset=offset, count=FILE_WRITE_CHUNK)
                    f.write(chunk)
                    if not truncated:
                        break
                    offset += len(chunk)
        except Exception as exc:
            raise AnsibleConnectionFailure(
                f"Failed to fetch file {in_path} from VM {self.get_option('vmid')}: {exc}"
            ) from exc

    def close(self):
        self._proxmox = None
        self._connected = False
        self._is_windows_guest = None
        super().close()

    def reset(self):
        self.close()
        self._connect()
