
"""
Decrypt IP Tunnel .ipt config exports.

This handles the config format used by the APK in this workspace:
<file>.ipt -> base64 -> XXTEA (yy.l / yy.o, DELTA 0x9A7393B4) -> JSON.

Key: double base64 of "UUVGa1pXUmhlVzhuY3lCWFpWUjFibTVsYkE9PQ==" -> "@Adedayo's WeTunnel"
Encrypt side reproduces the APK byte-for-byte (yy.o passes y/z swapped vs standard XXTEA).
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.text import Text
except ImportError:
    print("[*] installing rich...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "rich", "-q"])
    from rich.console import Console
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.text import Text

console = Console()

PATH_SHORTCUTS = {
    "~": "/data/data/com.termux/files/home",
    "√": "/sdcard",
}

KEY_B64_B64 = "UUVGa1pXUmhlVzhuY3lCWFpWUjFibTVsYkE9PQ=="
KEY = base64.b64decode(base64.b64decode(KEY_B64_B64))

DELTA = 0x9A7393B4
MASK32 = 0xFFFFFFFF


# ── XXTEA (defpackage.yy, classes2.dex) ───────────────────────────

def _mx(s, y, z, p, k, e):
    return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) & MASK32) ^ \
           (((s ^ y) + (k[(p & 3) ^ e] ^ z)) & MASK32)


def _to_ints(data: bytes, with_len: bool) -> list[int]:
    n = (len(data) >> 2) + (0 if (len(data) & 3) == 0 else 1)
    arr = [0] * (n + 1) if with_len else [0] * n
    if with_len:
        arr[n] = len(data)
    for i, b in enumerate(data):
        arr[i >> 2] |= (b & 0xFF) << ((i & 3) << 3)
    return arr


def _to_bytes(arr: list[int], use_len: bool) -> bytes | None:
    total = len(arr) << 2
    if use_len:
        length = arr[-1]
        if length < total - 7 or length > total - 4:
            return None
        total = length
    out = bytearray(total)
    for i in range(total):
        out[i] = (arr[i >> 2] >> ((i & 3) << 3)) & 0xFF
    return bytes(out)


def _key_words(key: bytes) -> list[int]:
    if len(key) != 16:
        padded = bytearray(16)
        padded[:min(16, len(key))] = key[:16]
        key = bytes(padded)
    return [int.from_bytes(key[i:i + 4], "little") for i in range(0, 16, 4)]


def xxtea_decrypt(ct: bytes, key: bytes = KEY) -> bytes | None:
    if not ct:
        return b""
    v = _to_ints(ct, False)
    k = _key_words(key)
    n = len(v)
    if n - 1 >= 1:
        rounds = 52 // n + 6
        y = v[0]
        s = (rounds * DELTA) & MASK32
        for _ in range(rounds):
            e = (s >> 2) & 3
            y2 = y
            for p in range(n - 1, 0, -1):
                y2 = (v[p] - _mx(s, y2, v[p - 1], p, k, e)) & MASK32
                v[p] = y2
            y = (v[0] - _mx(s, y2, v[n - 1], 0, k, e)) & MASK32
            v[0] = y
            s = (s - DELTA) & MASK32
    return _to_bytes(v, True)


def xxtea_encrypt(pt: bytes, key: bytes = KEY) -> bytes:
    if not pt:
        return b""
    v = _to_ints(pt, True)
    k = _key_words(key)
    n = len(v)
    if n - 1 >= 1:
        rounds = 52 // n + 6
        y = v[n - 1]
        s = 0
        for _ in range(rounds):
            s = (s + DELTA) & MASK32
            e = (s >> 2) & 3
            y2 = y
            for p in range(n - 1):
                y2 = (v[p] + _mx(s, v[p + 1], y2, p, k, e)) & MASK32
                v[p] = y2
            y = (v[n - 1] + _mx(s, v[0], y2, n - 1, k, e)) & MASK32
            v[n - 1] = y
    return _to_bytes(v, False) or b""


# ── .ipt parse / build ────────────────────────────────────────────

def b64decode_any(value: str) -> bytes:
    value = re.sub(r"\s", "", value)
    value = value.replace("%2B", "+").replace("%2F", "/").replace("%3D", "=")
    value += "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.b64decode(value, validate=False)
    except Exception:
        return base64.urlsafe_b64decode(value)


def _looks_like_json(data: bytes) -> bool:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return text.lstrip()[:1] in ("{", "[")


def parse_ipt_content(content: str) -> dict | list:
    text = content.strip()
    if "://" in text[:24]:
        text = text.split("://", 1)[1]
    if text.lstrip()[:1] in ("{", "["):
        return json.loads(text)

    candidates: list[bytes] = []
    try:
        candidates.append(b64decode_any(text))
    except Exception:
        pass
    candidates.append(text.encode("utf-8"))

    errors = []
    for ct in candidates:
        if not ct:
            continue
        pt = xxtea_decrypt(ct)
        if pt and _looks_like_json(pt):
            return json.loads(pt.decode("utf-8"))
        errors.append(f"xxtea len={len(ct)} -> {'not json' if pt else 'bad length word'}")
    raise ValueError("could not decrypt: " + "; ".join(errors[:3]))


def encrypt_to_ipt(config: dict | list) -> str:
    pt = json.dumps(config, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(xxtea_encrypt(pt)).decode("ascii")


def clean_json(value):
    """Parse embedded JSON strings (e.g. Config) into real objects and
    strip leftover escape junk (\\/ -> /) so output is clean readable JSON."""
    if isinstance(value, dict):
        return {k: clean_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clean_json(v) for v in value]
    if isinstance(value, str):
        stripped = value.strip()
        if stripped[:1] in ("{", "["):
            try:
                return clean_json(json.loads(stripped))
            except Exception:
                pass
        return value.replace("\\/", "/").replace('\\"', '"')
    return value


# ── embedded v2ray URIs (vless://, vmess://, trojan://, ss://) ─────

URI_PREFIXES = ("vless://", "vmess://", "trojan://", "ss://")


def find_v2ray_uri(result) -> str | None:
    if not isinstance(result, dict):
        return None
    for key in ("V2RayUri", "v2rayUri", "v2ray", "uri", "URI", "Link", "link"):
        v = result.get(key)
        if isinstance(v, str) and v.strip().lower().startswith(URI_PREFIXES):
            return v.strip()
    for container in (result.get("Server"), result.get("Config")):
        if isinstance(container, dict):
            for v in container.values():
                if isinstance(v, str) and v.strip().lower().startswith(URI_PREFIXES):
                    return v.strip()
    return None


def _b64url_decode(s: str) -> bytes:
    s = re.sub(r"\s", "", s)
    s += "=" * ((4 - len(s) % 4) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(s)
        except Exception:
            continue
    return b""


def parse_v2ray_uri(uri: str) -> dict:
    uri = uri.strip()
    scheme, rest = uri.split("://", 1)
    scheme = scheme.lower()
    info: dict = {"scheme": scheme}

    if "#" in rest:
        rest, frag = rest.split("#", 1)
        info["name"] = urllib.parse.unquote(frag)

    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)

    if scheme == "vmess":
        raw = json.loads(_b64url_decode(rest).decode("utf-8", "ignore"))
        info.update(
            address=raw.get("add"),
            port=int(raw.get("port") or 0),
            uuid=raw.get("id"),
            alterId=int(raw.get("aid") or 0),
            cipher=raw.get("scy") or "auto",
            network=raw.get("net") or "tcp",
            security=raw.get("tls") or "",
            host=raw.get("host") or "",
            path=urllib.parse.unquote(raw.get("path") or ""),
            sni=raw.get("sni") or "",
            name=raw.get("ps") or info.get("name", ""),
        )
        return info

    if "@" in rest:
        userinfo, hostpart = rest.rsplit("@", 1)
    else:
        userinfo, hostpart = "", rest

    if ":" in hostpart and hostpart.rsplit(":", 1)[-1].isdigit():
        host, port_s = hostpart.rsplit(":", 1)
        port = int(port_s)
    else:
        host, port = hostpart, 443
    host = host.strip("[]")

    if userinfo and scheme == "ss":
        dec = _b64url_decode(userinfo).decode("utf-8", "ignore")
        method, _, password = dec.partition(":")
        info["method"] = method
        info["password"] = password
    else:
        info["uuid"] = urllib.parse.unquote(userinfo) if userinfo else ""

    params = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
    info.update(
        address=host,
        port=port,
        encryption=params.get("encryption", ""),
        network=params.get("type") or params.get("net") or "tcp",
        security=params.get("security", ""),
        sni=params.get("sni") or params.get("peer", ""),
        host=params.get("host", ""),
        path=urllib.parse.unquote(params.get("path", "")),
        flow=params.get("flow", ""),
        alpn=params.get("alpn", ""),
        fp=params.get("fp", ""),
        serviceName=params.get("serviceName", ""),
        name=info.get("name", ""),
    )
    return info


def uri_to_outbound(info: dict) -> dict:
    scheme = info["scheme"]
    network = info.get("network") or "tcp"
    security = info.get("security") or "none"

    stream: dict = {"network": network, "security": security}
    if network == "ws":
        ws: dict = {"path": info.get("path") or "/"}
        if info.get("host"):
            ws["headers"] = {"Host": info["host"]}
        stream["wsSettings"] = ws
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": info.get("serviceName", "")}
    elif network in ("h2", "http"):
        stream["httpSettings"] = {"path": info.get("path") or "/"}

    if security in ("tls", "reality"):
        sni = info.get("sni") or info.get("host") or info.get("address")
        if security == "reality":
            stream["realitySettings"] = {"serverName": sni, "fingerprint": info.get("fp") or "chrome"}
        else:
            tls: dict = {"serverName": sni, "allowInsecure": True}
            if info.get("alpn"):
                tls["alpn"] = [a for a in info["alpn"].split(",") if a]
            stream["tlsSettings"] = tls

    ob: dict = {"tag": scheme.upper(), "settings": {}, "streamSettings": stream}
    if scheme in ("vless", "vmess"):
        ob["protocol"] = scheme
        user: dict = {"id": info.get("uuid"), "level": 8}
        if scheme == "vmess":
            user["alterId"] = info.get("alterId", 0)
            user["security"] = info.get("cipher") or "auto"
        else:
            user["encryption"] = info.get("encryption") or "none"
            if info.get("flow"):
                user["flow"] = info["flow"]
        ob["settings"]["vnext"] = [{
            "address": info.get("address"),
            "port": info.get("port"),
            "users": [user],
        }]
    elif scheme == "trojan":
        ob["protocol"] = "trojan"
        ob["settings"]["servers"] = [{
            "address": info.get("address"),
            "port": info.get("port"),
            "password": info.get("uuid"),
        }]
    elif scheme == "ss":
        ob["protocol"] = "shadowsocks"
        ob["settings"]["servers"] = [{
            "address": info.get("address"),
            "port": info.get("port"),
            "method": info.get("method", ""),
            "password": info.get("password", ""),
        }]
    return ob


def v2ray_full_config(outbound: dict) -> dict:
    return {
        "log": {"loglevel": "none"},
        "inbounds": [
            {"listen": "127.0.0.1", "port": 3080, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True, "userLevel": 8}},
            {"listen": "127.0.0.1", "port": 8880, "protocol": "http",
             "settings": {"userLevel": 8}},
        ],
        "outbounds": [outbound],
        "policy": {
            "levels": {"8": {"connIdle": 300, "downlinkOnly": 1,
                             "handshake": 4, "uplinkOnly": 1}},
            "system": {"statsOutboundUplink": False, "statsOutboundDownlink": False},
        },
        "stats": {},
    }


# ── bot-style card output ─────────────────────────────────────────

CREDIT_LINE = "├┈➤ 𝗗𝗲𝗰𝗿𝘆𝗽𝘁 𝗕𝘆: @snapdark_decoder"
CARD_FOOTER = (
    "├┈➤ ⎙ 𝘿𝙚𝙘𝙧𝙮𝙥𝙩 𝙎𝙪𝙘𝙘𝙚𝙨𝙨 ✓ ⎙\n"
    "├┈➤ 𝗟𝗶𝗻𝗸: @snapdark_decoder\n"
    "╰───────────────────╯"
)


def _ubold(s: str) -> str:
    """Render ASCII letters/digits in Unicode mathematical bold (𝗯𝗼𝗹𝗱 font)."""
    out = []
    for ch in s:
        o = ord(ch)
        if 0x41 <= o <= 0x5A:
            out.append(chr(0x1D5D4 + o - 0x41))
        elif 0x61 <= o <= 0x7A:
            out.append(chr(0x1D5EE + o - 0x61))
        elif 0x30 <= o <= 0x39:
            out.append(chr(0x1D7EC + o - 0x30))
        else:
            out.append(ch)
    return "".join(out)


def card_title(result, fallback=None) -> str:
    """App name of the config source, rendered in bold font."""
    if isinstance(result, dict):
        if any(k in result for k in ("ExpireDate", "Sig", "isXposed", "DeviceID", "Server", "Config")):
            return _ubold("IP Tunnel")
        if "outbounds" in result or find_v2ray_uri(result):
            return _ubold("V2ray")
    return _ubold("IP Tunnel")


def extract_summary(result):
    lines = []
    if not isinstance(result, dict):
        return lines

    if "outbounds" in result:
        for ob in result.get("outbounds") or []:
            proto = str(ob.get("protocol") or "")
            if not proto or proto in ("freedom", "blackhole", "block"):
                continue
            lines.append(f"🔹 Protocol : {proto.upper()}")
            sett = ob.get("settings") or {}
            vnext = sett.get("vnext") or []
            servers = sett.get("servers") or []
            if vnext:
                v = vnext[0]
                lines.append(f"🔹 Address  : {v.get('address')}:{v.get('port')}")
                users = v.get("users") or []
                if users:
                    uid = users[0].get("id") or users[0].get("password") or ""
                    if uid:
                        lines.append(f"🔹 User ID  : {uid}")
            elif servers:
                s0 = servers[0]
                addr = s0.get("address") or s0.get("server")
                lines.append(f"🔹 Address  : {addr}:{s0.get('port')}")
                if s0.get("method"):
                    lines.append(f"🔹 Method   : {s0.get('method')}")
                if s0.get("password"):
                    lines.append(f"🔹 Password : {s0.get('password')}")
            stream = ob.get("streamSettings") or {}
            net = stream.get("network")
            sec = stream.get("security")
            if net:
                val = str(net) + (f" / {sec}" if sec and sec != "none" else "")
                lines.append(f"🔹 Network  : {val}")
            ws = stream.get("wsSettings") or {}
            host = (ws.get("headers") or {}).get("Host")
            path = ws.get("path")
            if host:
                lines.append(f"🔹 Host     : {host}")
            if path:
                lines.append(f"🔹 Path     : {path}")
            grpc = stream.get("grpcSettings") or {}
            if grpc.get("serviceName"):
                lines.append(f"🔹 GRPC     : {grpc.get('serviceName')}")
            tls = stream.get("tlsSettings") or {}
            if sec in ("tls", "reality") and tls.get("serverName"):
                lines.append(f"🔹 SNI      : {tls.get('serverName')}")
            break
        return lines

    # IP Tunnel style: list EVERY field (like the app's field dump)
    keys = [k for k in result if k not in SIG_KEYS]
    width = max((len(str(k)) for k in keys), default=1)
    for key in keys:
        lines += _field_lines(key, result[key], width)
    return lines


SIG_KEYS = {"Sig", "SigAlg", "SigTs", "SigKid", "SigV"}


def _field_lines(key, val, width):
    """Format one config field; dict values become an indented sub-section."""
    if isinstance(val, dict):
        lines = [f"🔹 [{key}] :"]
        if not val:
            return [f"🔹 [{str(key).ljust(width)}] : "]
        sub_w = max((len(str(k)) for k in val), default=1)
        for k2, v2 in val.items():
            if isinstance(v2, dict):
                lines += _field_lines(k2, v2, sub_w)
            elif isinstance(v2, list):
                lines.append(f"   🔹 {str(k2).ljust(sub_w)} : {json.dumps(v2, ensure_ascii=False)}")
            else:
                lines.append(f"   🔹 {str(k2).ljust(sub_w)} : {'' if v2 is None else v2}")
        return lines

    if isinstance(val, list):
        value = json.dumps(val, ensure_ascii=False)
    else:
        value = "" if val is None else str(val)
    return [f"🔹 {str(key).ljust(width)} : {value}"]


def card_header(title) -> str:
    return f"╭•❀•❀ {title} ❀•❀•╮\n{CREDIT_LINE}"


def build_card(header: str, body: str) -> str:
    return f"{header}\n\n{body}\n\n{CARD_FOOTER}"


# ── UI ────────────────────────────────────────────────────────────

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def copy_to_clipboard(text):
    try:
        proc = subprocess.run(
            ["termux-clipboard-set"],
            input=text.encode("utf-8"),
            timeout=3,
        )
        return proc.returncode == 0
    except Exception:
        return False


def expand_path(path):
    path = path.strip()
    for shortcut, full_path in PATH_SHORTCUTS.items():
        if path.startswith(shortcut):
            path = full_path + path[len(shortcut):]
            break
    return path


def save_paths_for(filename: str, out_dir: str):
    if filename.endswith(".ipt"):
        base_name = filename[:-4]
    else:
        base_name = filename
    clean = re.sub(r'[\\/*?:"<>|]', "_", base_name).strip() or "Pasted_Config"
    return (
        f"{out_dir}/{clean}.txt",
        f"{out_dir}/{clean}_reenc.ipt",
    )


def display_result(header: str, body: str, card: str, ipt_json: str, result,
                   title_extra: str | None = None, out_dir: str = "/sdcard/Dec/IPTunnel", raw=None,
                   v2_json: str | None = None):
    console.print(Text(header, style="bold magenta"))
    console.print(Text(body))
    console.print()
    console.print(Text(CARD_FOOTER, style="bold green"))

    copy_text = card

    if title_extra:
        filename = title_extra
    else:
        name = None
        if isinstance(result, dict):
            name = result.get("Name") or result.get("name")
            cfg = result.get("Config")
            if not name and isinstance(cfg, dict):
                name = cfg.get("Name")
        filename = (re.sub(r'[\\/*?:"<>|]', "_", str(name)).strip() if name else "Pasted_Config")

    raw = raw if raw is not None else result
    save_path_txt, save_path_ipt = save_paths_for(filename, out_dir)
    save_path_v2 = f"{save_path_txt[:-4]}_v2ray.json" if v2_json else None

    while True:
        menu = Text()
        menu.append("1. ", style="bold cyan")
        menu.append("Copy To Clipboard 📋\n")
        menu.append("2. ", style="bold cyan")
        menu.append("Save To files:\n")
        menu.append(f"   - {save_path_txt}\n", style="dim")
        menu.append(f"   - {save_path_ipt}\n", style="dim")
        if save_path_v2:
            menu.append(f"   - {save_path_v2}\n", style="dim")
        menu.append("0. ", style="bold red")
        menu.append("Back")

        console.print(Panel(
            menu,
            title="Action Menu",
            border_style="blue",
            width=console.width,
        ))

        try:
            ans = console.input("\n[bold yellow]Select [0-2]: [/bold yellow]").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if ans == "1":
            if copy_to_clipboard(copy_text):
                console.print("[bold green]\nCopied To Clipboard 📋 !!![/bold green]\n")
            else:
                # Termux:API clipboard unavailable -> save card for manual copy
                try:
                    os.makedirs(out_dir, exist_ok=True)
                    fallback_path = f"{out_dir}/clipboard_card.txt"
                    with open(fallback_path, "w", encoding="utf-8") as f:
                        f.write(copy_text + "\n")
                    console.print(
                        f"[bold yellow]\nClipboard API unavailable (Termux:API app not connected).[/bold yellow]\n"
                        f"[bold yellow]Card saved:[/bold yellow] [cyan]{fallback_path}[/cyan]\n"
                        f"[dim]Open the file and copy, or long-press select the card above.[/dim]\n"
                    )
                except Exception as e:
                    console.print(f"[bold red]Copy failed: {e}[/bold red]\n")
            console.input("[bold yellow][Press Enter To Get Back To Main Menu][/bold yellow]")
            break
        elif ans == "2":
            try:
                os.makedirs(out_dir, exist_ok=True)
                with open(save_path_txt, "w", encoding="utf-8") as f:
                    f.write(ipt_json)
                reenc = encrypt_to_ipt(raw)
                with open(save_path_ipt, "w", encoding="ascii") as f:
                    f.write(reenc)
                # verify re-encrypt roundtrip before claiming success
                if json.loads(xxtea_decrypt(b64decode_any(reenc)).decode("utf-8")) != json.loads(json.dumps(raw)):
                    raise ValueError("re-encrypt roundtrip mismatch")
                saved = [f"1. {save_path_txt}", f"2. {save_path_ipt}"]
                if v2_json and save_path_v2:
                    with open(save_path_v2, "w", encoding="utf-8") as f:
                        f.write(v2_json)
                    saved.append(f"3. {save_path_v2}")
                console.print(
                    "[bold green]\nSaved successfully to:\n" + "\n".join(saved) + " !!![/bold green]\n"
                )
            except Exception as e:
                console.print(f"[bold red]Failed to save: {e}[/bold red]\n")
            console.input("[bold yellow][Press Enter To Get Back To Main Menu][/bold yellow]")
            break
        elif ans == "0":
            break
        else:
            console.print("[bold red]Invalid Choice...[/bold red]")


def decrypt_and_show(content: str, title_extra: str | None = None, out_dir: str = "/sdcard/Dec/IPTunnel"):
    try:
        result = parse_ipt_content(content)
        cleaned = clean_json(result)
        ipt_json = json.dumps(cleaned, indent=2, ensure_ascii=False)

        is_ipt = ("outbounds" not in cleaned) and any(
            k in cleaned for k in ("ExpireDate", "PSInstall", "isXposed", "DeviceID", "Sig", "Config", "Server")
        )

        title = card_title(cleaned, title_extra)
        header = card_header(title)
        summary = extract_summary(cleaned)

        body_lines: list[str] = []
        if is_ipt:
            body_lines.append("====================")
            body_lines += summary
            body_lines.append("====================")
            if title_extra:
                body_lines.append(title_extra)
        else:
            body_lines += summary
            body_lines.append("")
            body_lines.append("⚙️ Full JSON Config:")
            body_lines.append(ipt_json)

        v2_json = None
        uri = find_v2ray_uri(cleaned) if is_ipt else None
        if uri:
            outbound = uri_to_outbound(parse_v2ray_uri(uri))
            v2_json = json.dumps(v2ray_full_config(outbound), indent=2, ensure_ascii=False)
            body_lines.append("")
            body_lines.append("⚙️ Full JSON Config:")
            body_lines.append(v2_json)

        body = "\n".join(body_lines)
        card = build_card(header, body)
        display_result(
            header, body, card, ipt_json, cleaned,
            title_extra=title_extra, out_dir=out_dir, raw=result, v2_json=v2_json,
        )
    except Exception as e:
        console.print(Panel(
            f"[bold red]{e}[/bold red]",
            title="Error",
            border_style="red",
            expand=False,
        ))


def print_banner():
    clear_screen()
    banner_text = Text(
        "IP Tunnel Config Decryptor (.ipt, XXTEA)",
        style="bold cyan",
        justify="center",
    )
    console.print(Panel(
        banner_text,
        border_style="green",
        width=console.width,
        padding=(1, 2),
    ))


def print_menu():
    menu = Text()
    menu.append("1) ", style="bold cyan")
    menu.append("Select an IP Tunnel Config (.ipt)\n")
    menu.append("2) ", style="bold cyan")
    menu.append("Paste IP Tunnel Config (base64 / json)\n")
    menu.append("0) ", style="bold red")
    menu.append("Exit")

    console.print(Panel(
        menu,
        title="Main Menu",
        border_style="blue",
        width=console.width,
    ))


def option_file(out_dir: str):
    hint = Text()
    hint.append("Enter the file path\n\n", style="bold")
    hint.append("Shortcuts:\n", style="dim")
    hint.append("  ~  ", style="bold cyan")
    hint.append("= /data/data/com.termux/files/home\n", style="dim")
    hint.append("  √  ", style="bold cyan")
    hint.append("= /sdcard\n\n", style="dim")
    hint.append("Example: ", style="dim")
    hint.append("√/senseitunnel/কনফিগ.ipt", style="cyan")

    console.print(Panel(
        hint,
        title="File Selection",
        border_style="blue",
        expand=False,
        padding=(1, 2),
    ))

    try:
        raw_path = console.input("\n[bold yellow]Path: [/bold yellow]")
    except (EOFError, KeyboardInterrupt):
        return

    raw_path = raw_path.strip()
    if not raw_path:
        return

    filepath = expand_path(raw_path)

    if not os.path.isfile(filepath):
        console.print(Panel(
            f"[bold red]File not found:[/bold red]\n{filepath}",
            title="Error",
            border_style="red",
            expand=False,
        ))
        input("\n[Press Enter to continue]")
        return

    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        console.print(Panel(
            f"[bold red]{e}[/bold red]",
            title="Error",
            border_style="red",
            expand=False,
        ))
        input("\n[Press Enter to continue]")
        return

    filename = os.path.basename(filepath)
    console.print(f"\n[dim]File:[/dim] [cyan]{filepath}[/cyan]")
    console.print(f"[dim]Size:[/dim] [cyan]{len(content)} bytes[/cyan]\n")

    decrypt_and_show(content, title_extra=filename, out_dir=out_dir)


def option_paste(out_dir: str):
    console.print(Panel(
        "Paste your config below.\n"
        "Press [bold yellow]Enter twice[/bold yellow] to process.\n"
        "Accepts base64 (.ipt content) or raw [dim]{json}[/dim]",
        border_style="blue",
        expand=False,
        padding=(1, 2),
    ))
    print()

    lines = []
    try:
        while True:
            print(">> ", end="", flush=True)
            line = input()
            if not line.strip():
                break
            lines.append(line)
    except (EOFError, KeyboardInterrupt):
        pass

    if not lines:
        return

    full_input = "".join(line.strip() for line in lines) if "://" in "".join(lines) \
        else "\n".join(lines)
    decrypt_and_show(full_input, out_dir=out_dir)


def main():
    out_dir = "/sdcard/Dec/IPTunnel"
    while True:
        print_banner()
        print_menu()

        try:
            choice = console.input(
                "\n[bold yellow]Select [0-2]: [/bold yellow]"
            ).strip()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == "1":
            print_banner()
            option_file(out_dir)

        elif choice == "2":
            print_banner()
            option_paste(out_dir)

        elif choice == "0":
            clear_screen()
            console.print("[bold yellow]Goodbye !!![/bold yellow]")
            time.sleep(0.5)
            clear_screen()
            break

        else:
            console.print("[bold red]Invalid Choice...[/bold red]")


if __name__ == "__main__":
    main()
