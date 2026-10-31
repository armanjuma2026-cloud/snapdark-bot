
"""
Decrypt SnapDark Tunnel config exports (formerly DARK Tunnel).

This handles the config format used by the APK in this workspace:
darktunnel:// / snapdarktunnel://<base64url-json> -> encryptedLockedConfig -> AES-CFB -> msgpack.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from struct import unpack
from typing import Any
from urllib.parse import quote, urlencode

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

try:
    from cryptography.hazmat.decrepit.ciphers import modes
except ImportError:
    from cryptography.hazmat.primitives.ciphers import modes

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text

console = Console()
PATH_SHORTCUTS = {
    "~": "/data/data/com.termux/files/home",
    "√": "/sdcard",
}

OUTER_KEY = b"$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd"
INNER_KEY = b"F)J@NcRfUjXn2r4u7x!A%D*G"
IV = bytes.fromhex("232e39185523184a5723586242200e05")

PLACEHOLDER_TOKEN_RE = re.compile(r"(?<=:)(\$[A-Z0-9_]+)(?=\s*[,}\]])")


class MsgpackReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read(self, size: int) -> bytes:
        end = self.pos + size
        if end > len(self.data):
            raise ValueError("truncated msgpack data")
        chunk = self.data[self.pos:end]
        self.pos = end
        return chunk

    def read_u8(self) -> int:
        return self.read(1)[0]

    def read_str(self, size: int) -> str:
        return self.read(size).decode("utf-8")

    def read_map(self, size: int) -> dict[Any, Any]:
        return {self.unpack(): self.unpack() for _ in range(size)}

    def read_array(self, size: int) -> list[Any]:
        return [self.unpack() for _ in range(size)]

    def unpack(self) -> Any:
        code = self.read_u8()

        if code <= 0x7F:
            return code
        if code >= 0xE0:
            return code - 0x100
        if 0x80 <= code <= 0x8F:
            return self.read_map(code & 0x0F)
        if 0x90 <= code <= 0x9F:
            return self.read_array(code & 0x0F)
        if 0xA0 <= code <= 0xBF:
            return self.read_str(code & 0x1F)

        if code == 0xC0:
            return None
        if code == 0xC2:
            return False
        if code == 0xC3:
            return True
        if code == 0xC4:
            return self.read(self.read_u8())
        if code == 0xC5:
            return self.read(unpack(">H", self.read(2))[0])
        if code == 0xC6:
            return self.read(unpack(">I", self.read(4))[0])
        if code == 0xCA:
            return unpack(">f", self.read(4))[0]
        if code == 0xCB:
            return unpack(">d", self.read(8))[0]
        if code == 0xCC:
            return self.read_u8()
        if code == 0xCD:
            return unpack(">H", self.read(2))[0]
        if code == 0xCE:
            return unpack(">I", self.read(4))[0]
        if code == 0xCF:
            return unpack(">Q", self.read(8))[0]
        if code == 0xD0:
            return unpack(">b", self.read(1))[0]
        if code == 0xD1:
            return unpack(">h", self.read(2))[0]
        if code == 0xD2:
            return unpack(">i", self.read(4))[0]
        if code == 0xD3:
            return unpack(">q", self.read(8))[0]
        if code == 0xD9:
            return self.read_str(self.read_u8())
        if code == 0xDA:
            return self.read_str(unpack(">H", self.read(2))[0])
        if code == 0xDB:
            return self.read_str(unpack(">I", self.read(4))[0])
        if code == 0xDC:
            return self.read_array(unpack(">H", self.read(2))[0])
        if code == 0xDD:
            return self.read_array(unpack(">I", self.read(4))[0])
        if code == 0xDE:
            return self.read_map(unpack(">H", self.read(2))[0])
        if code == 0xDF:
            return self.read_map(unpack(">I", self.read(4))[0])

        raise ValueError(f"unsupported msgpack marker 0x{code:02x}")


def msgpack_unpack(data: bytes) -> Any:
    reader = MsgpackReader(data)
    value = reader.unpack()
    if reader.pos != len(data):
        raise ValueError(f"msgpack has {len(data) - reader.pos} trailing bytes")
    return value


def b64decode_any(value: str) -> bytes:
    value = value.strip()
    value = value.replace("%2B", "+").replace("%2F", "/").replace("%3D", "=")
    value += "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(value)
    except:
        return base64.b64decode(value)


def aes_cfb_decrypt(data: bytes, key: bytes) -> bytes:
    return Cipher(algorithms.AES(key), modes.CFB(IV)).decryptor().update(data)


def parse_dark_content(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("snapdarktunnel://") or text.startswith("darktunnel://"):
        text = text.split("://", 1)[1]
        return json.loads(b64decode_any(text))
    return json.loads(text)


def maybe_parse_text(text: str) -> Any:
    stripped = text.strip()
    if stripped[:1] in ("{", "["):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass
    return text


def bytes_for_json(value: bytes) -> Any:
    if len(value) == 96:
        head = value[:64]
        tail = value[64:]
        try:
            head_text = head.decode("ascii")
            if all(ch in "0123456789abcdefABCDEF" for ch in head_text):
                return {
                    "hash_hex": head_text,
                    "extra_hash_hex": tail.hex(),
                    "length": len(value),
                }
        except UnicodeDecodeError:
            pass

    try:
        return maybe_parse_text(value.decode("utf-8"))
    except UnicodeDecodeError:
        return {
            "bytes_b64": base64.b64encode(value).decode("ascii"),
            "bytes_hex": value.hex(),
            "length": len(value),
        }


def json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(json_safe(k)): json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, bytes):
        return bytes_for_json(value)
    return value


def decrypt_value(value: bytes) -> Any:
    if not value:
        return ""
    return bytes_for_json(aes_cfb_decrypt(value, INNER_KEY))


def decrypt_inner_fields(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            key_text = key.decode("utf-8") if isinstance(key, bytes) else str(key)
            if key_text.startswith("Encrypted") and isinstance(item, bytes):
                clean_key = key_text[len("Encrypted") :]
                out[clean_key] = decrypt_value(item)
            else:
                out[key_text] = decrypt_inner_fields(item)
        return out
    if isinstance(value, list):
        return [decrypt_inner_fields(item) for item in value]
    if isinstance(value, bytes):
        return bytes_for_json(value)
    return value


def to_camel_case(d: Any) -> Any:
    if isinstance(d, dict):
        new_d: dict[str, Any] = {}
        for k, v in d.items():
            if isinstance(k, str) and k:
                if k == "V2RayConfig":
                    new_k = "v2rayConfig"
                elif k == "SshConfig":
                    new_k = "sshConfig"
                elif k == "InjectConfig":
                    new_k = "injectConfig"
                elif k == "DnsttDnsHost":
                    new_k = "dnsttUdpDnsHost"
                elif k == "DnsttDnsPort":
                    new_k = "dnsttUdpDnsPort"
                elif k == "DnsttPubkey":
                    new_k = "dnsttPublicKey"
                else:
                    new_k = k[0].lower() + k[1:]
                new_d[new_k] = to_camel_case(v)
            else:
                new_d[k] = to_camel_case(v)
        return new_d
    elif isinstance(d, list):
        return [to_camel_case(i) for i in d]
    else:
        return d


def create_unlocked_config(config_dict: dict[str, Any]) -> dict[str, Any]:
    unlocked = json.loads(json.dumps(config_dict))
    decrypted_locked = unlocked.pop("decryptedLockedConfig", {})
    inner_config = decrypted_locked.get("DecryptedInnerConfig")
    
    if inner_config:
        camel_inner = to_camel_case(inner_config)
        tunnel_type = unlocked.get("type", "")
        
        # Build correct camelCase tunnelConfig key
        parts = tunnel_type.lower().split('_')
        tunnel_config_key = parts[0] + ''.join(p.capitalize() for p in parts[1:]) + "TunnelConfig"
        
        if tunnel_config_key not in unlocked:
            unlocked[tunnel_config_key] = {}
            
        for k, v in camel_inner.items():
            if isinstance(v, dict):
                v.pop("isEncrypted", None)
                v.pop("isLocked", None)
                
                # Special parsing for V2RayConfig to extract UI fields
                if k == "v2rayConfig" and "config" in v:
                    if tunnel_type == "V2RAY_CUSTOM_CONFIG":
                        if isinstance(v["config"], dict):
                            unlocked[tunnel_config_key]["v2rayCustomConfig"] = json.dumps(v.pop("config"))
                        else:
                            unlocked[tunnel_config_key]["v2rayCustomConfig"] = str(v.pop("config"))
                        v.pop("isInjectModeEnabled", None)
                    else:
                        try:
                            if isinstance(v["config"], str):
                                safe_json = re.sub(r':\s*\$[A-Z0-9_]+', ': true', v["config"])
                                v2_data = json.loads(safe_json)
                            else:
                                v2_data = v["config"]
                                
                            outbounds = v2_data.get("outbounds", [])
                            if outbounds:
                                ob = outbounds[0]
                                settings = ob.get("settings", {})
                                stream = ob.get("streamSettings", {})
                                
                                vnext = settings.get("vnext", [{}])[0]
                                users = vnext.get("users", [{}])[0]
                                if not vnext and settings.get("servers"):
                                    vnext = settings.get("servers", [{}])[0]
                                    users = vnext
                                    
                                v["host"] = vnext.get("address", "")
                                v["port"] = vnext.get("port", 443)
                                v["uuid"] = users.get("id", "") or users.get("password", "")
                                v["serverNameIndication"] = stream.get("tlsSettings", {}).get("serverName", "")
                                
                                net = stream.get("network", "")
                                if net == "ws":
                                    v["wsPath"] = stream.get("wsSettings", {}).get("path", "")
                                    v["wsHeaderHost"] = stream.get("wsSettings", {}).get("headers", {}).get("Host", "")
                                elif net == "grpc":
                                    v["grpcServiceName"] = stream.get("grpcSettings", {}).get("serviceName", "")
                        except Exception:
                            pass
                        
                        v.pop("config", None)
                        v.pop("isInjectModeEnabled", None)

                # Convert known integer fields
                for int_key in ["port", "proxyPort", "dnsttUdpDnsPort"]:
                    if int_key in v:
                        try:
                            v[int_key] = int(v[int_key])
                        except ValueError:
                            pass
                            
                # Merge with existing
                if k in unlocked[tunnel_config_key] and isinstance(unlocked[tunnel_config_key][k], dict):
                    unlocked[tunnel_config_key][k].update(v)
                else:
                    unlocked[tunnel_config_key][k] = v
                    
        # Special mapping for SSH_DNSTT where injectConfig becomes dnsttConfig
        if tunnel_type == "SSH_DNSTT":
            inj = unlocked[tunnel_config_key].pop("injectConfig", {})
            if inj:
                unlocked[tunnel_config_key]["dnsttConfig"] = {
                    "udpDnsHost": inj.get("dnsttUdpDnsHost", ""),
                    "serverName": inj.get("dnsttServerName", ""),
                    "publicKey": inj.get("dnsttPublicKey", "")
                }
                port = inj.get("dnsttUdpDnsPort")
                if port and port != 53 and port != "53":
                    unlocked[tunnel_config_key]["dnsttConfig"]["udpDnsPort"] = int(port)
                    
        # Cleanup empty configs and drop meaningless empty strings
        for k in list(unlocked[tunnel_config_key].keys()):
            val = unlocked[tunnel_config_key][k]
            if isinstance(val, dict):
                keys_to_delete = [sub_k for sub_k, sub_v in val.items() if sub_v == ""]
                for sub_k in keys_to_delete:
                    # Do not delete payload if it's empty!
                    if sub_k != "payload":
                        del val[sub_k]
                
                if not val:
                    del unlocked[tunnel_config_key][k]
                elif k == "sshConfig" and not val.get("host") and not val.get("username"):
                    del unlocked[tunnel_config_key][k]
                elif k == "injectConfig" and not val.get("proxyHost") and "payload" not in val and not val.get("dnsttServerName"):
                    del unlocked[tunnel_config_key][k]
                elif k == "v2rayConfig" and not val.get("host") and not val.get("uuid"):
                    del unlocked[tunnel_config_key][k]
                    
    return unlocked


def first_match(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, flags=re.DOTALL)
    if not match:
        return None
    return match.group(1).replace(r"\/", "/")


def extract_vless_details(config_text: str, name: str | None = None) -> dict[str, Any]:
    details: dict[str, Any] = {}

    fields = {
        "address": r'"address"\s*:\s*"([^"]+)"',
        "port": r'"port"\s*:\s*(\d+)',
        "id": r'"id"\s*:\s*"([^"]+)"',
        "network": r'"network"\s*:\s*"([^"]+)"',
        "streamSecurity": r'"streamSettings"\s*:\s*\{.*?"security"\s*:\s*"([^"]+)"',
        "host": r'"Host"\s*:\s*"([^"]*)"',
        "path": r'"path"\s*:\s*"([^"]*)"',
        "encryption": r'"encryption"\s*:\s*"([^"]+)"',
        "flow": r'"flow"\s*:\s*"([^"]*)"',
    }

    for key, pattern in fields.items():
        value = first_match(pattern, config_text)
        if value is not None:
            details[key] = int(value) if key == "port" else value

    if {"address", "port", "id"} <= details.keys():
        params = {
            "encryption": details.get("encryption", "none"),
            "security": details.get("streamSecurity", "none"),
            "type": details.get("network", "tcp"),
        }
        if details.get("host"):
            params["host"] = details["host"]
        if details.get("path"):
            params["path"] = details["path"]
        if details.get("flow"):
            params["flow"] = details["flow"]

        query = urlencode(params, quote_via=quote, safe="")
        label = quote(name or "dark-config", safe="")
        details["vlessUri"] = (
            f"vless://{details['id']}@{details['address']}:{details['port']}?{query}#{label}"
        )

    return details


def add_readable_v2ray_config(result: dict[str, Any]) -> None:
    decrypted = result.get("decryptedConfig")
    if not isinstance(decrypted, dict):
        return

    v2ray = decrypted.get("V2RayConfig")
    if not isinstance(v2ray, dict):
        return

    config_text = v2ray.get("Config")
    if not isinstance(config_text, str) or not config_text:
        return

    v2ray["ConfigText"] = config_text
    visible = result.get("visibleConfig")
    name = visible.get("name") if isinstance(visible, dict) else None
    details = extract_vless_details(config_text, str(name) if name else None)
    if details:
        v2ray["ExtractedConnection"] = details


def add_readable_ssh_config(result: dict[str, Any]) -> None:
    decrypted = result.get("decryptedConfig")
    if not isinstance(decrypted, dict):
        return

    ssh = decrypted.get("SshConfig")
    if not isinstance(ssh, dict):
        return

    host = str(ssh.get("Host") or "").strip()
    port = str(ssh.get("Port") or "").strip()
    username = str(ssh.get("Username") or "").strip()
    password = str(ssh.get("Password") or "").strip()
    if not host or not port:
        return

    link = f"{host}:{port}@{username}:{password}"
    ssh["Link"] = link
    ssh["ExtractedConnection"] = {
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "link": link,
    }

    links = result.setdefault("connectionLinks", {})
    if isinstance(links, dict):
        links["ssh"] = link


def process_dark_config(content: str, source_name: str = "Pasted") -> dict[str, Any]:
    try:
        config = parse_dark_content(content)
    except Exception as e:
        raise ValueError(f"Invalid JSON or Base64 format: {e}")

    encrypted = config.pop("encryptedLockedConfig", None)

    if encrypted:
        outer_msgpack = aes_cfb_decrypt(b64decode_any(encrypted), OUTER_KEY)
        outer = msgpack_unpack(outer_msgpack)
        
        locked_app = outer.get("LockedAppConfig", {}) if isinstance(outer, dict) else {}
        inner_blob = outer.get("EncryptedLockedConfig", b"") if isinstance(outer, dict) else b""
        
        decrypted_inner = None
        if isinstance(inner_blob, bytes) and inner_blob:
            inner_msgpack = aes_cfb_decrypt(inner_blob, INNER_KEY)
            inner = msgpack_unpack(inner_msgpack)
            decrypted_inner = decrypt_inner_fields(inner)
        
        config["decryptedLockedConfig"] = {
            "LockedAppConfig": json_safe(locked_app),
            "DecryptedInnerConfig": decrypted_inner
        }

    return config

# ======================= UI/UX =======================

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def copy_to_clipboard(text):
    try:
        proc = subprocess.run(
            ["termux-clipboard-set"],
            input=text.encode("utf-8"),
            timeout=5,
        )
        return proc.returncode == 0
    except Exception:
        return False

def display_result(text, result, title_extra=None):
    title = "Decrypted JSON"
    if title_extra:
        title = f"{title_extra} - {title}"

    content = Syntax(text, "json", theme="monokai", word_wrap=True)

    console.print(Panel(
        content,
        title=title,
        border_style="green",
        expand=False,
        padding=(1, 2),
    ))

    if title_extra:
        filename = title_extra
    else:
        visible_name = result.get("name")
        if visible_name:
            clean_name = re.sub(r'[\\/*?:"<>|]', "_", str(visible_name)).strip()
            filename = clean_name if clean_name else "Pasted_Config"
        else:
            filename = "Pasted_Config"
            
    if filename.endswith(".dark"):
        base_name = filename[:-5]
    else:
        base_name = filename
        
    save_path_txt = f"/sdcard/Dec/DarkTunnel/{filename}.txt"
    save_path_unlocked = f"/sdcard/Dec/DarkTunnel/{base_name}_unlocked.dark"

    while True:
        menu = Text()
        menu.append("1. ", style="bold cyan")
        menu.append("Copy To Clipboard 📋\n")
        menu.append("2. ", style="bold cyan")
        menu.append("Save To files:\n")
        menu.append(f"   - {save_path_txt}\n", style="dim")
        menu.append(f"   - {save_path_unlocked}\n", style="dim")
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
            if copy_to_clipboard(text):
                console.print("[bold green]\nCopied To Clipboard 📋 !!![/bold green]\n")
            else:
                console.print("[bold red]Copy Failed.[/bold red]\n")
            console.input("[bold yellow][Press Enter To Get Back To Main Menu][/bold yellow]")
            break
        elif ans == "2":
            try:
                os.makedirs("/sdcard/Dec/DarkTunnel", exist_ok=True)
                with open(save_path_txt, "w", encoding="utf-8") as f:
                    f.write(text)
                
                unlocked_json = create_unlocked_config(result)
                unlocked_text = json.dumps(unlocked_json, separators=(',', ':'))
                b64_encoded = base64.b64encode(unlocked_text.encode("utf-8")).decode("utf-8")
                
                with open(save_path_unlocked, "w", encoding="utf-8") as f:
                    f.write(f"darktunnel://{b64_encoded}")
                    
                console.print(f"[bold green]\nSaved successfully to:\n1. {save_path_txt}\n2. {save_path_unlocked} !!![/bold green]\n")
            except Exception as e:
                console.print(f"[bold red]Failed to save: {e}[/bold red]\n")
            console.input("[bold yellow][Press Enter To Get Back To Main Menu][/bold yellow]")
            break
        elif ans == "0":
            break
        else:
            console.print("[bold red]Invalid Choice...[/bold red]")

def decrypt_and_show(content, title_extra=None):
    try:
        result = process_dark_config(content, source_name=title_extra or "Pasted")
        text = json.dumps(result, indent=2, ensure_ascii=False)
        display_result(text, result, title_extra)
    except ValueError as e:
        console.print(Panel(
            f"[bold red]{e}[/bold red]",
            title="Error",
            border_style="red",
            expand=False,
        ))

def expand_path(path):
    path = path.strip()
    for shortcut, full_path in PATH_SHORTCUTS.items():
        if path.startswith(shortcut):
            path = full_path + path[len(shortcut):]
            break
    return path

def print_banner():
    clear_screen()
    banner_text = Text("SnapDark Tunnel Config Decryptor (.dark, snapdarktunnel://)", style="bold cyan", justify="center")
    console.print(Panel(
        banner_text,
        border_style="green",
        width=console.width,
        padding=(1, 2),
    ))

def print_menu():
    menu = Text()
    menu.append("1) ", style="bold cyan")
    menu.append("Select a SnapDark Tunnel Config (.dark)\n")
    menu.append("2) ", style="bold cyan")
    menu.append("Paste SnapDark Tunnel Config (snapdarktunnel://)\n")
    menu.append("0) ", style="bold red")
    menu.append("Exit")

    console.print(Panel(
        menu,
        title="Main Menu",
        border_style="blue",
        width=console.width,
    ))

def option_paste():
    console.print(Panel(
        "Paste your config below.\n"
        "Press [bold yellow]Enter twice[/bold yellow] to process.\n"
        "Accepts raw json or [dim]snapdarktunnel://...[/dim]",
        border_style="blue",
        expand=False,
        padding=(1, 2),
    ))
    print()

    while True:
        try:
            print(">> ", end="", flush=True)
            lines = []
            if sys.platform != "win32" and sys.stdin.isatty():
                import termios
                fd = sys.stdin.fileno()
                old_settings = termios.tcgetattr(fd)
                new_settings = termios.tcgetattr(fd)
                new_settings[3] = new_settings[3] & ~termios.ICANON
                try:
                    termios.tcsetattr(fd, termios.TCSADRAIN, new_settings)
                    while True:
                        chars = []
                        while True:
                            c = sys.stdin.read(1)
                            if not c or c == '\x04':
                                break
                            if c in ('\n', '\r'):
                                sys.stdout.write('\n')
                                sys.stdout.flush()
                                break
                            if c == '\x7f' or c == '\x08':
                                if chars:
                                    chars.pop()
                                    sys.stdout.write('\b \b')
                                    sys.stdout.flush()
                                continue
                            chars.append(c)
                        line = "".join(chars)
                        if not line.strip():
                            break
                        lines.append(line)
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            else:
                while True:
                    line = input()
                    if not line.strip():
                        break
                    lines.append(line)
            
            if not lines:
                break
                
            full_input = "\n".join(lines)
            if "snapdarktunnel://" in full_input or "darktunnel://" in full_input:
                full_input = "".join(line.strip() for line in lines)
                
            decrypt_and_show(full_input)
            break
        except (EOFError, KeyboardInterrupt):
            break

def option_file():
    hint = Text()
    hint.append("Enter the file path\n\n", style="bold")
    hint.append("Shortcuts:\n", style="dim")
    hint.append("  ~  ", style="bold cyan")
    hint.append("= /data/data/com.termux/files/home\n", style="dim")
    hint.append("  √  ", style="bold cyan")
    hint.append("= /sdcard\n\n", style="dim")
    hint.append("Example: ", style="dim")
    hint.append("√/Download/Test.dark", style="cyan")

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

    decrypt_and_show(content, title_extra=filename)

def main():
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
            option_file()

        elif choice == "2":
            print_banner()
            option_paste()

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
