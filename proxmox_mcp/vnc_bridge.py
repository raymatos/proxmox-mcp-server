"""Local RFB bridge presenting a stable VNC endpoint backed by Proxmox console tickets.

Proxmox hands out an ephemeral port and a single-use ticket per console session, so a VNC
client configured with static host/port/password (which is every off-the-shelf VNC MCP) cannot
talk to it. This bridge sits in between:

  vnc client  --->  127.0.0.1:5901  --->  pve node :590x  --->  VM console

On each inbound connection it reads the current target, mints a fresh ticket, completes the
VNC authentication upstream itself, and presents the client a plain RFB stream. Once both
handshakes are done it is a blind byte relay, so the client negotiates encodings directly with
QEMU and every encoding QEMU offers keeps working.

The target is a small JSON file (written by the set_console_target MCP tool):

    {"env": "~/.config/proxmox-mcp/cbg01.env", "node": "pve01", "vmid": 174}

Because the target names its own env file, one bridge covers every node — clustered or not.

Run with:  python -m proxmox_mcp.vnc_bridge
"""

from __future__ import annotations

import asyncio
import json
import os
import struct
import sys
from pathlib import Path

import httpx
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

TARGET_FILE = Path(
    os.getenv("PROXMOX_CONSOLE_TARGET", Path.home() / ".config/proxmox-mcp/console-target.json")
)
LISTEN_HOST = os.getenv("PROXMOX_VNC_BRIDGE_HOST", "127.0.0.1")
LISTEN_PORT = int(os.getenv("PROXMOX_VNC_BRIDGE_PORT", "5901"))
# Optional downstream password. Unset means the loopback endpoint takes no auth.
DOWNSTREAM_PASSWORD = os.getenv("PROXMOX_VNC_BRIDGE_PASSWORD", "")

RFB_VERSION = b"RFB 003.008\n"
SEC_NONE, SEC_VNC = 1, 2


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def vnc_des(challenge: bytes, password: str) -> bytes:
    """VNC auth response: DES-ECB with the password's first 8 bytes, each byte bit-reversed."""
    key = password.encode()[:8].ljust(8, b"\0")
    key = bytes(int(f"{b:08b}"[::-1], 2) for b in key)
    enc = Cipher(TripleDES(key), modes.ECB()).encryptor()  # 8-byte key == single DES
    return enc.update(challenge) + enc.finalize()


def read_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def load_target() -> tuple[dict[str, str], str, int]:
    if not TARGET_FILE.exists():
        raise RuntimeError(
            f"no console target set ({TARGET_FILE} missing) — call set_console_target first"
        )
    t = json.loads(TARGET_FILE.read_text())
    env_path = Path(os.path.expanduser(t["env"]))
    if not env_path.exists():
        raise RuntimeError(f"env file {env_path} referenced by the target does not exist")
    return read_env_file(env_path), t["node"], int(t["vmid"])


async def mint_console(env: dict[str, str], node: str, vmid: int) -> tuple[str, int, str]:
    """Ask Proxmox for a one-shot console port + ticket."""
    host, port = env["PROXMOX_HOST"], env.get("PROXMOX_PORT", "8006")
    auth = (
        f"PVEAPIToken={env['PROXMOX_USER']}!{env['PROXMOX_TOKEN_NAME']}="
        f"{env['PROXMOX_TOKEN_VALUE']}"
    )
    verify = env.get("PROXMOX_VERIFY_SSL", "false").lower() == "true"
    async with httpx.AsyncClient(verify=verify, timeout=20.0) as c:
        r = await c.post(
            f"https://{host}:{port}/api2/json/nodes/{node}/qemu/{vmid}/vncproxy",
            headers={"Authorization": auth},
            data={"websocket": 0},
        )
        r.raise_for_status()
        d = r.json()["data"]
    return host, int(d["port"]), d["ticket"]


async def upstream_handshake(r: asyncio.StreamReader, w: asyncio.StreamWriter, ticket: str) -> bytes:
    """Do the RFB 3.8 client side against Proxmox. Returns the raw ServerInit block."""
    await r.readexactly(12)
    w.write(RFB_VERSION)
    await w.drain()

    types = list(await r.readexactly((await r.readexactly(1))[0]))
    if SEC_VNC not in types:
        raise RuntimeError(f"upstream offered no VNC auth, got {types}")
    w.write(bytes([SEC_VNC]))
    await w.drain()

    w.write(vnc_des(await r.readexactly(16), ticket))
    await w.drain()
    if struct.unpack(">I", await r.readexactly(4))[0] != 0:
        raise RuntimeError("upstream VNC auth rejected the console ticket")

    w.write(bytes([1]))  # ClientInit, shared
    await w.drain()

    head = await r.readexactly(24)  # width, height, 16-byte pixel format, name length
    name_len = struct.unpack(">I", head[20:24])[0]
    return head + await r.readexactly(name_len)


async def downstream_handshake(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    """Do the RFB 3.8 server side toward the local VNC client."""
    w.write(RFB_VERSION)
    await w.drain()
    await r.readexactly(12)

    if DOWNSTREAM_PASSWORD:
        w.write(bytes([1, SEC_VNC]))
        await w.drain()
        if (await r.readexactly(1))[0] != SEC_VNC:
            raise RuntimeError("client refused VNC auth")
        challenge = os.urandom(16)
        w.write(challenge)
        await w.drain()
        ok = await r.readexactly(16) == vnc_des(challenge, DOWNSTREAM_PASSWORD)
        w.write(struct.pack(">I", 0 if ok else 1))
        await w.drain()
        if not ok:
            raise RuntimeError("client failed bridge authentication")
    else:
        w.write(bytes([1, SEC_NONE]))
        await w.drain()
        if (await r.readexactly(1))[0] != SEC_NONE:
            raise RuntimeError("client refused the None security type")
        w.write(struct.pack(">I", 0))
        await w.drain()

    await r.readexactly(1)  # ClientInit; we always share upstream


async def pump(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    try:
        while chunk := await r.read(65536):
            w.write(chunk)
            await w.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        w.close()


async def handle_client(cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
    peer = cw.get_extra_info("peername")
    uw = None
    try:
        env, node, vmid = load_target()
        host, port, ticket = await mint_console(env, node, vmid)
        log(f"[bridge] {peer} -> {node}/{vmid} via {host}:{port}")

        ur, uw = await asyncio.open_connection(host, port)
        server_init = await upstream_handshake(ur, uw, ticket)
        await downstream_handshake(cr, cw)

        cw.write(server_init)
        await cw.drain()
        w, h = struct.unpack(">HH", server_init[:4])
        log(f"[bridge] connected: {w}x{h}")

        await asyncio.gather(pump(ur, cw), pump(cr, uw))
    except Exception as e:  # noqa: BLE001 - one bad session must not kill the listener
        log(f"[bridge] session failed: {type(e).__name__}: {e}")
    finally:
        for s in (cw, uw):
            if s is not None and not s.is_closing():
                s.close()


async def main() -> None:
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    log(f"[bridge] listening on {LISTEN_HOST}:{LISTEN_PORT}, target file {TARGET_FILE}")
    log(f"[bridge] downstream auth: {'password' if DOWNSTREAM_PASSWORD else 'none (loopback)'}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
