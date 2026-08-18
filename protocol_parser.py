"""
Parses VPN config links (vless/vmess/trojan/ss/hysteria2) into:
  - a sing-box outbound dict, used only for testing connectivity
  - the original remark (name/tag) pulled from the URI fragment

Rebuilding the final link only requires swapping the fragment, so a config
is never re-serialized from scratch - the original link is kept intact
except for the "#remark" part.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote, quote


FLAG_RE = re.compile(r'([\U0001F1E6-\U0001F1FF]{2})')


@dataclass
class ParsedConfig:
    protocol: str
    outbound: dict
    remark: str
    raw: str


class ParseError(ValueError):
    pass


def _b64pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def _b64decode(s: str) -> bytes:
    s = s.strip()
    try:
        return base64.urlsafe_b64decode(_b64pad(s))
    except (binascii.Error, ValueError):
        return base64.b64decode(_b64pad(s))


def extract_flag_emoji(text: str) -> str:
    m = FLAG_RE.search(text or "")
    return m.group(1) if m else ""


def replace_remark(raw_uri: str, new_remark: str) -> str:
    base = raw_uri.split("#", 1)[0]
    return f"{base}#{quote(new_remark)}"


def build_final_link(raw_uri: str, protocol: str, new_remark: str) -> str:
    """Rebuilds a link with a new display name. vmess stores its name
    inside the base64-encoded JSON body (the "ps" field), not in the URL
    fragment, so it needs special handling; everything else just gets its
    #fragment swapped."""
    if protocol == "vmess":
        payload = raw_uri[len("vmess://"):]
        try:
            data = json.loads(_b64decode(payload))
        except Exception:
            return replace_remark(raw_uri, new_remark)
        data["ps"] = new_remark
        new_payload = base64.b64encode(
            json.dumps(data, separators=(",", ":")).encode()
        ).decode()
        return "vmess://" + new_payload
    return replace_remark(raw_uri, new_remark)


def _get_remark(fragment: str) -> str:
    return unquote(fragment) if fragment else ""


# ---------------------------------------------------------------- vless ----
def _parse_vless(uri: str) -> ParsedConfig:
    p = urlparse(uri)
    uuid_ = p.username
    host, port = p.hostname, p.port
    if not (uuid_ and host and port):
        raise ParseError("incomplete vless link")
    q = {k: v[0] for k, v in parse_qs(p.query).items()}
    net = q.get("type", "tcp")
    security = q.get("security", "none")

    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "uuid": uuid_,
        "packet_encoding": "xudp",
    }
    if q.get("flow"):
        outbound["flow"] = q["flow"]
    _attach_transport(outbound, net, q)
    _attach_tls(outbound, security, q, host)
    return ParsedConfig("vless", outbound, _get_remark(p.fragment), uri)


# ---------------------------------------------------------------- vmess ----
def _parse_vmess(uri: str) -> ParsedConfig:
    payload = uri[len("vmess://"):]
    try:
        data = json.loads(_b64decode(payload))
    except Exception as e:
        raise ParseError(f"bad vmess payload: {e}")

    host = data.get("add")
    port = int(data.get("port", 0) or 0)
    uuid_ = data.get("id")
    if not (host and port and uuid_):
        raise ParseError("incomplete vmess link")

    net = data.get("net", "tcp")
    tls = data.get("tls", "")
    outbound = {
        "type": "vmess",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "uuid": uuid_,
        "security": "auto",
        "alter_id": int(data.get("aid", 0) or 0),
    }
    q = {
        "path": data.get("path", ""),
        "host": data.get("host", ""),
        "serviceName": data.get("path", ""),
        "sni": data.get("sni", "") or data.get("host", ""),
        "fp": data.get("fp", ""),
        # некоторые генераторы кладут флаг пропуска проверки сертификата
        # прямо в vmess JSON под этим именем
        "allowInsecure": str(data.get("allowInsecure", "")),
    }
    _attach_transport(outbound, net, q)
    _attach_tls(outbound, "tls" if tls == "tls" else "none", q, host)
    remark = data.get("ps", "")
    return ParsedConfig("vmess", outbound, remark, uri)


# --------------------------------------------------------------- trojan ----
def _parse_trojan(uri: str) -> ParsedConfig:
    p = urlparse(uri)
    password = p.username
    host, port = p.hostname, p.port
    if not (password and host and port):
        raise ParseError("incomplete trojan link")
    q = {k: v[0] for k, v in parse_qs(p.query).items()}
    net = q.get("type", "tcp")

    outbound = {
        "type": "trojan",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "password": unquote(password),
    }
    _attach_transport(outbound, net, q)
    _attach_tls(outbound, q.get("security", "tls"), q, host)
    return ParsedConfig("trojan", outbound, _get_remark(p.fragment), uri)


# -------------------------------------------------------------------- ss ----
def _parse_ss(uri: str) -> ParsedConfig:
    p = urlparse(uri)
    remark = _get_remark(p.fragment)

    # ФИКС: ссылки с SIP003-плагином (obfs-local / v2ray-plugin, параметр
    # ?plugin=...) раньше проходили парсинг молча, plugin просто
    # отбрасывался, и sing-box пытался подключиться напрямую без
    # обфускации. Сервер такое соединение почти всегда отклоняет, и
    # рабочий конфиг попадал в "нерабочие" без внятной причины. В образе
    # нет бинарников плагинов, поэтому честно помечаем такие ссылки как
    # неподдерживаемые вместо того, чтобы тратить слот на заведомо
    # обречённую проверку и путать статистику.
    q = {k: v[0] for k, v in parse_qs(p.query).items()}
    if q.get("plugin"):
        raise ParseError("ss with SIP003 plugin is not supported")

    if p.username and p.hostname and p.port:
        userinfo = p.username
        password = unquote(p.password) if p.password else ""
        if password:
            method = unquote(userinfo)
        else:
            try:
                decoded = _b64decode(userinfo).decode()
                method, password = decoded.split(":", 1)
            except Exception as e:
                raise ParseError(f"bad ss userinfo: {e}")
        host, port = p.hostname, p.port
    else:
        body = uri[len("ss://"):].split("#", 1)[0]
        try:
            decoded = _b64decode(body).decode()
            creds, hostport = decoded.rsplit("@", 1)
            method, password = creds.split(":", 1)
            host, port_s = hostport.rsplit(":", 1)
            port = int(port_s)
        except Exception as e:
            raise ParseError(f"bad ss link: {e}")

    outbound = {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "method": method,
        "password": password,
    }
    return ParsedConfig("shadowsocks", outbound, remark, uri)


# ------------------------------------------------------------ hysteria2 ----
def _parse_hysteria2(uri: str) -> ParsedConfig:
    p = urlparse(uri)
    password = p.username or ""
    host, port = p.hostname, p.port
    if not (host and port):
        raise ParseError("incomplete hysteria2 link")
    q = {k: v[0] for k, v in parse_qs(p.query).items()}

    outbound = {
        "type": "hysteria2",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "password": unquote(password),
        "tls": {
            "enabled": True,
            "server_name": q.get("sni", host),
            "insecure": q.get("insecure", "0") in ("1", "true", "True"),
        },
    }
    obfs = q.get("obfs")
    if obfs:
        outbound["obfs"] = {"type": obfs, "password": q.get("obfs-password", "")}
    return ParsedConfig("hysteria2", outbound, _get_remark(p.fragment), uri)


def _attach_transport(outbound: dict, net: str, q: dict) -> None:
    if net == "ws":
        headers = {"Host": q["host"]} if q.get("host") else {}
        outbound["transport"] = {"type": "ws", "path": q.get("path", "/"), "headers": headers}
    elif net == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": q.get("serviceName", "")}
    elif net == "http":
        host_list = [q["host"]] if q.get("host") else []
        outbound["transport"] = {"type": "http", "path": q.get("path", "/"), "host": host_list}
    # tcp / raw: no transport block needed


def _is_truthy(value: Optional[str]) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes")


def _attach_tls(outbound: dict, security: str, q: dict, default_sni: str) -> None:
    if security in ("tls", "reality"):
        # ФИКС: раньше insecure всегда было False, из-за чего конфиги с
        # самоподписанным сертификатом (allowInsecure=1 / insecure=1 в
        # ссылке — обычное дело для личных vless/trojan серверов) не
        # проходили TLS-хендшейк в sing-box и ошибочно считались нерабочими,
        # хотя в любом реальном клиенте (v2rayN, nekoray и т.д.) этот же
        # флаг из ссылки заставил бы клиент пропустить проверку сертификата.
        insecure = _is_truthy(q.get("allowInsecure")) or _is_truthy(q.get("insecure"))
        tls = {
            "enabled": True,
            "server_name": q.get("sni") or default_sni,
            "insecure": insecure,
        }
        fp = q.get("fp")
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        if security == "reality":
            tls["reality"] = {
                "enabled": True,
                "public_key": q.get("pbk", ""),
                "short_id": q.get("sid", ""),
            }
        outbound["tls"] = tls


_SCHEME_PARSERS = {
    "vless": _parse_vless,
    "vmess": _parse_vmess,
    "trojan": _parse_trojan,
    "ss": _parse_ss,
    "hysteria2": _parse_hysteria2,
    "hy2": _parse_hysteria2,
}


def parse_config(raw_line: str) -> ParsedConfig:
    raw_line = raw_line.strip()
    scheme = raw_line.split("://", 1)[0].lower() if "://" in raw_line else ""
    parser = _SCHEME_PARSERS.get(scheme)
    if not parser:
        raise ParseError(f"unsupported scheme: {scheme or raw_line[:20]}")
    return parser(raw_line)
