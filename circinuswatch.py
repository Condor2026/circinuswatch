
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CircinusWatch v8.1 — Passive OSINT & Web Security Audit
Author: Condor2026 | Hardened + Ethical Edition
"""

import asyncio
import fnmatch
import hashlib
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import stat
import sys
import threading
import time
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urljoin, urlparse

APP_NAME = "CircinusWatch"
APP_VERSION = "8.1"

try:
    import requests
    import whois
    from bs4 import BeautifulSoup
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
    from rich.prompt import Prompt, Confirm
    from rich import box
    from rich.traceback import install
    from rich.text import Text
    from rich.markup import escape
    from requests.structures import CaseInsensitiveDict

    install(show_locals=False)
    print("✅ Dependencias cargadas correctamente")
except ImportError as e:
    print(f"❌ Faltan dependencias: {e}")
    print("📦 pip install --break-system-packages rich requests python-whois beautifulsoup4 flask")
    sys.exit(1)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(SCRIPT_DIR)

console = Console()

LOG_FILE = "logs/events.json"
THREATS_DB = "logs/threats.json"
SCAN_HISTORY = "logs/scan_history.json"
BLACKLIST_FILE = "data/blacklist.json"
WHITELIST_FILE = "data/whitelist.json"
REPUTATION_DB = "data/reputation.json"
REPORT_FILE = "logs/reports.json"
WATCHLIST_FILE = "data/watchlist.json"
CONFIG_FILE = "config.json"

MAX_BODY_BYTES = 2_000_000
PAGE_TEXT_LIMIT = 250_000
MAX_REDIRECTS = 5
MAX_EVENTS = 20_000
MAX_THREATS = 5_000
MAX_SCANS = 1_000
MAX_BATCH_TARGETS = 50

_ALLOW_PRIVATE = os.environ.get("CIRCINUS_ALLOW_PRIVATE", "").strip() == "1"

# ============================================================
# 🔑 API KEYS — EDITA SOLO ESTA SECCIÓN
# ============================================================
VT_API_KEY = "TU_API_KEY"
ABUSEIPDB_API_KEY = ""
GREYNOISE_API_KEY = ""
SHODAN_API_KEY = ""
GSB_API_KEY = ""
URLHAUS_AUTH_KEY = ""
TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID = ""
# ============================================================

_SECRETS = set()
_SECRET_PATTERNS = [
    (re.compile(r'(?i)\b(key|apikey|api_key|token|auth-key)=([^&\s\'"]+)'), r'\1=***'),
    (re.compile(r'bot\d{5,}:[A-Za-z0-9_\-]{20,}'), 'bot***'),
]


def _register_secret(value):
    if value and len(value) >= 6:
        _SECRETS.add(value)


def _redact(text):
    s = str(text)
    for secret in _SECRETS:
        s = s.replace(secret, '***')
    for rx, rep in _SECRET_PATTERNS:
        s = rx.sub(rep, s)
    return s


def _safe_err(e, limit=100):
    return _redact(str(e))[:limit]


for _k in (VT_API_KEY, ABUSEIPDB_API_KEY, GREYNOISE_API_KEY, SHODAN_API_KEY,
           GSB_API_KEY, URLHAUS_AUTH_KEY, TELEGRAM_BOT_TOKEN):
    _register_secret(_k)

os.makedirs("logs", exist_ok=True)
os.makedirs("data", exist_ok=True)
os.makedirs("reports", exist_ok=True)
os.makedirs("backups", exist_ok=True)


def _mask(key):
    if not key:
        return "no detectada"
    if len(key) >= 16:
        return f"detectada (…{key[-4:]})"
    return "detectada"


_NARRATIVE_LEXICON = {
    "dehumanizacion": [
        r"\bnazi(?:s|sta|stas)?\b", r"\bfascista(?:s)?\b",
        r"\brata(?:s)?\b", r"\balimaña(?:s)?\b", r"\bplaga\b",
        r"\bpar[aá]sito(?:s)?\b", r"\bescoria\b", r"\binfecto(?:s)?\b",
        r"\bsubhumanos?\b", r"\borcos?\b", r"\bruzzian?s?\b",
    ],
    "belicismo": [
        r"\bdesnazificaci[oó]n\b", r"\boperaci[oó]n especial\b",
        r"\bgenocidio\b", r"\blimpieza [eé]tnica\b", r"\bguerra santa\b",
        r"\bneutralizaci[oó]n\b", r"\bpurga\b", r"\baniquilaci[oó]n\b",
    ],
    "deslegitimacion_institucional": [
        r"\bgolpe de estado\b", r"\br[eé]gimen(?:es)?\b",
        r"\bdictador(?:a|es|as)?\b", r"\btitere\b",
        r"\bmarioneta(?:s)?\b", r"\bquinta columna\b",
        r"\btraidor(?:es|a|as)?\b", r"\bcolaboracionista(?:s)?\b",
    ],
    "apelacion_emocional": [
        r"\bbioterrorismo\b", r"\brusofobia\b", r"\bucranofobia\b",
        r"\bantiamericanismo\b", r"\banti-?otan\b", r"\banti-?rusia\b",
        r"\bm[aá]rtires?\b", r"\bsangre derramada\b",
    ],
    "atribucion_sin_prueba": [
        r"\bseg[uú]n fuentes\b", r"\bpresuntamente\b",
        r"\bsupuestamente\b", r"\bal parecer\b", r"\bfuentes an[oó]nimas\b",
    ],
}

_NARRATIVE_DIRECTIONAL = {
    "pro_ru": [
        r"\brusofobia\b", r"\boperaci[oó]n especial\b", r"\bdesnazificaci[oó]n\b",
        r"\bjunta de kiev\b", r"\banglosajones?\b", r"\boccidente colectivo\b",
    ],
    "pro_ua": [
        r"\bucranofobia\b", r"\binvasi[oó]n rusa\b", r"\bcriminal(?:es)? de guerra\b",
        r"\bterrorismo ruso\b", r"\borcos?\b", r"\bruzzian?s?\b",
    ],
    "pro_otan": [
        r"\bimperialismo ruso\b", r"\bmundo libre\b", r"\bvalores occidentales\b",
    ],
    "anti_otan": [
        r"\bimperialismo (?:yankee|americano|occidental)\b",
        r"\bhegemon[ií]a (?:yankee|americana|occidental)\b",
        r"\bexpansionismo de la otan\b",
    ],
}


def _compile_narrative():
    lex = {k: [re.compile(p, re.IGNORECASE | re.UNICODE) for p in pats]
           for k, pats in _NARRATIVE_LEXICON.items()}
    direc = {k: [re.compile(p, re.IGNORECASE | re.UNICODE) for p in pats]
             for k, pats in _NARRATIVE_DIRECTIONAL.items()}
    return lex, direc


_NARR_LEX, _NARR_DIR = _compile_narrative()

NARRATIVE_DISCLAIMER = (
    "Detecta MARCADORES LINGÜÍSTICOS de encuadre beligerante. "
    "NO determina veracidad, intención ni bando. Requiere revisión humana."
)


def analyze_narrative_text(text):
    out = {
        "total_markers": 0, "categories": {}, "examples": {},
        "balance": {}, "framing_intensity": 0.0,
        "disclaimer": NARRATIVE_DISCLAIMER,
    }
    if not text or len(text) < 50:
        return out
    total_words = max(len(text.split()), 1)
    for cat, regexes in _NARR_LEX.items():
        hits = []
        for rx in regexes:
            hits.extend(m.group(0).lower() for m in rx.finditer(text))
        if hits:
            out["categories"][cat] = len(hits)
            out["examples"][cat] = list(dict.fromkeys(hits))[:8]
    for side, regexes in _NARR_DIR.items():
        hits = []
        for rx in regexes:
            hits.extend(m.group(0).lower() for m in rx.finditer(text))
        if hits:
            out["balance"][side] = len(hits)
    out["total_markers"] = sum(out["categories"].values())
    density = (out["total_markers"] / total_words) * 1000
    out["framing_intensity"] = round(min(density / 20.0, 1.0), 3)
    return out


_IO_LOCK = threading.RLock()


def _read_json(path, default):
    with _IO_LOCK:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            return default
        except json.JSONDecodeError:
            try:
                os.replace(path, f"{path}.corrupt-{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            except Exception:
                pass
            return default
        except Exception:
            return default


def _write_json(path, data):
    with _IO_LOCK:
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        tmp = f"{path}.{os.getpid()}.tmp"
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)


def _append_json_list(path, item, max_items):
    with _IO_LOCK:
        data = _read_json(path, [])
        if not isinstance(data, list):
            data = []
        data.append(item)
        _write_json(path, data[-max_items:])


if not os.path.exists(WATCHLIST_FILE):
    _write_json(WATCHLIST_FILE, {})


_HOST_LABEL_RE = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?<!-)$')
GEO_HINT_SUFFIXES = ('.ru', '.su', '.рф', '.xn--p1ai', '.by')


def _geo_hint(target):
    host = _extract_host(target) or (target or "").lower()
    return any(host.endswith(s) for s in GEO_HINT_SUFFIXES)


def _extract_host(target):
    t = (target or "").strip()
    if not t:
        return ""
    try:
        parsed = urlparse(t if '://' in t else f"//{t}")
        host = (parsed.hostname or "").strip().lower().rstrip('.')
    except ValueError:
        return ""
    return host


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _api_domain(target):
    host = _extract_host(target)
    if not host or _is_ip(host):
        return host
    try:
        return host.encode('idna').decode('ascii')
    except UnicodeError:
        return host


def validate_target(target):
    t = (target or "").strip()
    if not t:
        return False, "objetivo vacío"
    if len(t) > 2048:
        return False, "demasiado largo"
    if any(ord(c) < 32 or c.isspace() for c in t):
        return False, "contiene espacios o caracteres de control"
    if '://' in t:
        try:
            if urlparse(t).scheme.lower() not in ('http', 'https'):
                return False, "solo esquemas http/https"
        except ValueError:
            return False, "URL malformada"
    host = _extract_host(t)
    if not host:
        return False, "no se pudo extraer host"
    if _is_ip(host):
        return True, ""
    try:
        ascii_host = host.encode('idna').decode('ascii')
    except UnicodeError:
        return False, "dominio inválido (IDNA)"
    if len(ascii_host) > 253:
        return False, "dominio demasiado largo"
    labels = ascii_host.split('.')
    if len(labels) < 2 or not all(_HOST_LABEL_RE.match(lbl) for lbl in labels):
        return False, "dominio mal formado"
    return True, ""


def _host_is_public(host):
    if _ALLOW_PRIVATE:
        return True, ""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True, ""
    for info in infos:
        addr = info[4][0].split('%')[0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if not ip.is_global:
            return False, f"{host} resuelve a {addr} (no pública)"
    return True, ""


def _resolve_public_ip(target):
    host = _extract_host(target)
    if not host:
        return None, "objetivo vacío"
    try:
        ip = host if _is_ip(host) else socket.gethostbyname(host)
    except Exception as e:
        return None, f"No resuelve: {_safe_err(e, 60)}"
    if not _ALLOW_PRIVATE:
        try:
            if not ipaddress.ip_address(ip).is_global:
                return None, f"IP no pública ({ip})"
        except ValueError:
            return None, "IP inválida"
    return ip, None


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
]

EMOJIS = {
    'critical': '💀', 'high': '🔴', 'medium': '🟡', 'low': '🟢',
    'safe': '✅', 'info': 'ℹ', 'warning': '⚠', 'success': '🎯',
    'scan': '🔍', 'target': '🎯', 'narrative': '🗣', 'cyber': '💻',
    'whois': '📋', 'geo': '🌍', 'ports': '🔌', 'report': '📊',
    'dashboard': '📈', 'stats': '📉', 'backup': '💾', 'export': '📤',
}


async def _guard(coro, default):
    try:
        return await coro
    except Exception as e:
        d = dict(default) if isinstance(default, dict) else default
        if isinstance(d, dict):
            d["error"] = f"{type(e).__name__}: {_safe_err(e)}"
        return d


class WarLogger:
    def __init__(self):
        dict_files = [BLACKLIST_FILE, WHITELIST_FILE, REPUTATION_DB]
        list_files = [LOG_FILE, THREATS_DB, SCAN_HISTORY, REPORT_FILE]
        for f in dict_files + list_files:
            if not os.path.exists(f):
                _write_json(f, {} if f in dict_files else [])

    @staticmethod
    def _event_id(*parts):
        return hashlib.sha256("".join(parts).encode()).hexdigest()[:8]

    def log_event(self, origin, level, message, details=None):
        now_iso = datetime.now().isoformat()
        event = {"timestamp": now_iso, "origin": origin, "level": level,
                 "message": message, "details": details or {},
                 "id": self._event_id(origin, message, now_iso)}
        _append_json_list(LOG_FILE, event, MAX_EVENTS)
        if level == "CRITICAL":
            _append_json_list(THREATS_DB, event, MAX_THREATS)
        self._update_reputation(origin, level)
        return event['id']

    def log_scan(self, target, results):
        now_iso = datetime.now().isoformat()
        _append_json_list(SCAN_HISTORY,
                          {"timestamp": now_iso, "target": target, "results": results,
                           "id": self._event_id(target, now_iso)}, MAX_SCANS)

    def _update_reputation(self, target, level):
        try:
            with _IO_LOCK:
                rep = _read_json(REPUTATION_DB, {})
                if not isinstance(rep, dict):
                    rep = {}
                if target not in rep:
                    rep[target] = {"score": 0, "last_seen": datetime.now().isoformat(),
                                   "incidents": []}
                points = {"CRITICAL": -10, "WARNING": -3, "INFO": 1}
                rep[target]['score'] += points.get(level, 0)
                rep[target]['last_seen'] = datetime.now().isoformat()
                rep[target]['incidents'].append({"time": datetime.now().isoformat(),
                                                 "level": level,
                                                 "score_change": points.get(level, 0)})
                rep[target]['incidents'] = rep[target]['incidents'][-100:]
                _write_json(REPUTATION_DB, rep)
        except Exception:
            pass

    def get_last_events(self, n=10):
        data = _read_json(LOG_FILE, [])
        return data[-n:] if data else []

    def get_all_events(self):
        data = _read_json(LOG_FILE, [])
        return data if isinstance(data, list) else []

    def get_threats(self):
        data = _read_json(THREATS_DB, [])
        return data if isinstance(data, list) else []

    def get_reputation(self, target=None):
        rep = _read_json(REPUTATION_DB, {})
        if not isinstance(rep, dict):
            rep = {}
        if target:
            return rep.get(target, {"score": 0, "last_seen": "Nunca", "incidents": []})
        return rep

    def get_stats(self):
        logs = self.get_all_events()
        threats = self.get_threats()
        rep = self.get_reputation()
        hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
        recent = len([l for l in logs if l.get('level') in ['CRITICAL', 'WARNING']
                      and l.get('timestamp', '') > hour_ago])
        total = len(logs) or 1
        return {
            "total_events": len(logs),
            "critical": len([l for l in logs if l.get('level') == 'CRITICAL']),
            "warning": len([l for l in logs if l.get('level') == 'WARNING']),
            "info": len([l for l in logs if l.get('level') == 'INFO']),
            "total_threats": len(threats),
            "last_scan": logs[-1]['timestamp'] if logs else "Nunca",
            "unique_targets": len(set([l.get('origin') for l in logs])),
            "recent_threats": recent,
            "threat_rate": len(threats) / total,
            "avg_reputation": sum([v['score'] for v in rep.values()]) / len(rep) if rep else 0,
        }

    def clear_logs(self):
        for f in [LOG_FILE, THREATS_DB, SCAN_HISTORY]:
            _write_json(f, [])
        _write_json(REPUTATION_DB, {})

    def backup_logs(self):
        backup_file = f"backups/backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        data = {"logs": self.get_all_events(), "threats": self.get_threats(),
                "reputation": self.get_reputation(), "timestamp": datetime.now().isoformat()}
        _write_json(backup_file, data)
        return backup_file


logger = WarLogger()


class ReputationAnalyzer:
    def __init__(self):
        self.blacklist = self._load(BLACKLIST_FILE)
        self.whitelist = self._load(WHITELIST_FILE)

    def _load(self, path):
        data = _read_json(path, {})
        return data if isinstance(data, dict) else {}

    def check_blacklist(self, target):
        t = (target or "").lower()
        for pattern in self.blacklist:
            p = pattern.lower().strip()
            if p and p in t:
                return self.blacklist[pattern]
        return None

    def check_whitelist(self, target):
        t = (target or "").lower().strip()
        host = _extract_host(t) or t
        for pattern in self.whitelist:
            p = pattern.lower().strip()
            if not p:
                continue
            if '*' in p:
                if fnmatch.fnmatch(host, p) or fnmatch.fnmatch(t, p):
                    return self.whitelist[pattern]
            elif host == p or host.endswith('.' + p) or t == p:
                return self.whitelist[pattern]
        return None

    def add_to_blacklist(self, target, reason="Manual"):
        target = target.strip().lower()
        if not target:
            return False
        self.blacklist[target] = {"added": datetime.now().isoformat(), "reason": reason}
        _write_json(BLACKLIST_FILE, self.blacklist)
        return True

    def add_to_whitelist(self, target, reason="Manual"):
        target = target.strip().lower()
        if not target:
            return False
        self.whitelist[target] = {"added": datetime.now().isoformat(), "reason": reason}
        _write_json(WHITELIST_FILE, self.whitelist)
        return True

    def remove_from_blacklist(self, target):
        if target in self.blacklist:
            del self.blacklist[target]
            _write_json(BLACKLIST_FILE, self.blacklist)
            return True
        return False

    def remove_from_whitelist(self, target):
        if target in self.whitelist:
            del self.whitelist[target]
            _write_json(WHITELIST_FILE, self.whitelist)
            return True
        return False


class WatchlistManager:
    def __init__(self):
        self.watchlist = self._load()

    def _load(self):
        data = _read_json(WATCHLIST_FILE, {})
        return data if isinstance(data, dict) else {}

    def _save(self):
        _write_json(WATCHLIST_FILE, self.watchlist)

    def add(self, target):
        if target not in self.watchlist:
            self.watchlist[target] = {"added": datetime.now().isoformat(),
                                      "last_risk_score": None, "last_risk_level": None,
                                      "last_web_security_level": None, "last_checked": None}
            self._save()
            return True
        return False

    def remove(self, target):
        if target in self.watchlist:
            del self.watchlist[target]
            self._save()
            return True
        return False

    def update(self, target, risk_score, risk_level, web_security_level):
        if target not in self.watchlist:
            self.add(target)
        entry = self.watchlist[target]
        changed = (entry.get("last_risk_level") != risk_level) or \
                  (entry.get("last_web_security_level") != web_security_level)
        entry.update(last_risk_score=risk_score, last_risk_level=risk_level,
                     last_web_security_level=web_security_level,
                     last_checked=datetime.now().isoformat())
        self._save()
        return changed


class CircinusScanner:
    def __init__(self, vt_api_key=None, abuseipdb_key=None, greynoise_key=None,
                 shodan_key=None, gsb_key=None, urlhaus_auth_key=None,
                 telegram_token=None, telegram_chat_id=None):
        self.vt_api_key = vt_api_key
        self.abuseipdb_key = abuseipdb_key
        self.greynoise_key = greynoise_key
        self.shodan_key = shodan_key
        self.gsb_key = gsb_key
        self.urlhaus_auth_key = urlhaus_auth_key
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id
        for k in (vt_api_key, abuseipdb_key, greynoise_key, shodan_key,
                  gsb_key, urlhaus_auth_key, telegram_token):
            _register_secret(k)
        self.watchlist_analyzer = WatchlistManager()
        self.mode = "LEXICON_SYMMETRIC"
        console.print("✅ Análisis narrativo simétrico cargado", markup=False)

        self.suspicious_signatures = [
            {'pattern': r'eval\s*\(\s*(atob|unescape|decodeURI|String\.fromCharCode)',
             'type': 'JS Obfuscación', 'severity': 'Alta', 'desc': 'Ofuscación de código'},
            {'pattern': r'base64_decode', 'type': 'PHP base64_decode',
             'severity': 'Alta', 'desc': 'Ofuscación de código'},
            {'pattern': r'crypto_mine|coinhive', 'type': 'Cryptominer',
             'severity': 'Alta', 'desc': 'Minero de criptomonedas'},
            {'pattern': r'<iframe[^>]*style="display:none', 'type': 'IFrame Oculto',
             'severity': 'Alta', 'desc': 'Iframe invisible'},
            {'pattern': r'<iframe[^>]*width="0"[^>]*height="0"', 'type': 'IFrame Oculto',
             'severity': 'Alta', 'desc': 'Iframe tamaño 0'},
            {'pattern': r'\.apk["\']', 'type': 'Enlace a APK', 'severity': 'Media',
             'desc': 'Ejecutable Android'},
            {'pattern': r'\.exe["\']', 'type': 'Enlace a EXE', 'severity': 'Media',
             'desc': 'Ejecutable Windows'},
            {'pattern': r'wp-admin.{0,100}install', 'type': 'WordPress Exploit',
             'severity': 'Media', 'desc': 'Referencia a instalación WP'},
        ]

        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.mw', '.top', '.xyz',
                                '.club', '.online', '.site', '.click']

        self.security_headers_list = {
            'Strict-Transport-Security': {'name': 'HSTS', 'severity': 'Media',
                'title': 'HSTS no configurado', 'detail': 'Forzar HTTPS',
                'recommendation': 'max-age=31536000; includeSubDomains; preload'},
            'X-Frame-Options': {'name': 'X-Frame-Options', 'severity': 'Alta',
                'title': 'Riesgo de Clickjacking', 'detail': 'Permite framing',
                'recommendation': 'SAMEORIGIN o DENY'},
            'X-Content-Type-Options': {'name': 'X-Content-Type-Options', 'severity': 'Media',
                'title': 'MIME Sniffing no configurado', 'detail': 'Ataques MIME sniffing',
                'recommendation': 'nosniff'},
            'X-XSS-Protection': {'name': 'X-XSS-Protection', 'severity': 'Baja',
                'title': 'X-XSS-Protection no configurada (obsoleta)',
                'detail': 'Defensa real: CSP',
                'recommendation': '0 + CSP estricta'},
            'Content-Security-Policy': {'name': 'CSP', 'severity': 'Media',
                'title': 'CSP no configurado', 'detail': 'Política ausente',
                'recommendation': "default-src 'self'"},
            'Referrer-Policy': {'name': 'Referrer-Policy', 'severity': 'Baja',
                'title': 'Referrer-Policy no configurado', 'detail': 'Expone referer',
                'recommendation': 'strict-origin-when-cross-origin'},
            'Permissions-Policy': {'name': 'Permissions-Policy', 'severity': 'Baja',
                'title': 'Permissions-Policy no configurado',
                'detail': 'Sin restricción de features',
                'recommendation': "geolocation=(), microphone=(), camera=()"},
        }

        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        self.scan_count = 0
        self.reputation_analyzer = ReputationAnalyzer()

    async def get_whois(self, target):
        host = _extract_host(target) or target
        try:
            w = whois.whois(host)
            return {"domain": host,
                    "registrar": str(w.registrar)[:100] if w.registrar else "N/A",
                    "creation_date": str(w.creation_date) if w.creation_date else "N/A",
                    "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A",
                    "country": w.country if w.country else "N/A"}
        except Exception as e:
            return {"domain": host, "error": f"WHOIS error: {_safe_err(e, 80)}"}

    async def get_geolocation(self, target):
        try:
            ip, err = _resolve_public_ip(target)
            if err:
                return {"country": "No disponible", "error": err}
            response = requests.get(f"https://ipinfo.io/{ip}/json",
                                    headers={'User-Agent': random.choice(USER_AGENTS)}, timeout=8)
            if response.status_code != 200:
                return {"ip": ip, "country": "No disponible", "error": f"HTTP {response.status_code}"}
            data = response.json()
            return {"ip": ip, "country": data.get("country", "Desconocido"),
                    "city": data.get("city", "Desconocido"),
                    "org": data.get("org", "Desconocido")[:50]}
        except Exception as e:
            return {"country": "No disponible", "error": _safe_err(e, 80)}

    def _safe_fetch(self, url, headers):
        current = url
        hops = 0
        elapsed = 0.0
        while True:
            host = _extract_host(current)
            ok, why = _host_is_public(host)
            if not ok:
                raise ValueError(f"Bloqueado (anti-SSRF): {why}")
            resp = requests.get(current, headers=headers, timeout=(10, 25),
                                verify=True, allow_redirects=False, stream=True)
            elapsed += resp.elapsed.total_seconds()
            location = resp.headers.get('Location')
            if resp.is_redirect and location:
                resp.close()
                hops += 1
                if hops > MAX_REDIRECTS:
                    raise ValueError("Demasiadas redirecciones")
                nxt = urljoin(current, location)
                if urlparse(nxt).scheme.lower() not in ('http', 'https'):
                    raise ValueError("Redirección a esquema no permitido")
                current = nxt
                continue
            body = bytearray()
            truncated = False
            for chunk in resp.iter_content(chunk_size=16384):
                body.extend(chunk)
                if len(body) >= MAX_BODY_BYTES:
                    truncated = True
                    break
            try:
                set_cookies = list(resp.raw.headers.getlist('Set-Cookie'))
            except Exception:
                set_cookies = []
            encoding = resp.encoding or 'utf-8'
            try:
                text = bytes(body).decode(encoding, errors='replace')
            except LookupError:
                text = bytes(body).decode('utf-8', errors='replace')
            final_url = resp.url
            status = resp.status_code
            headers_out = CaseInsensitiveDict(resp.headers)
            resp.close()
            return {"ok": True, "url": url, "final_url": final_url,
                    "status_code": status, "headers": headers_out,
                    "set_cookies": set_cookies,
                    "content": text[:PAGE_TEXT_LIMIT],
                    "size": len(body), "truncated": truncated,
                    "time": elapsed, "redirects": hops}

    async def fetch_page(self, target):
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        attempts = []
        explicit_scheme = target.startswith('http')
        if explicit_scheme:
            attempts.append(target)
        else:
            attempts.append(f"https://{target}")
            attempts.append(f"http://{target}")
        last_error = "Sin intentos"
        for url in attempts:
            try:
                result = await asyncio.to_thread(self._safe_fetch, url, headers)
                result["downgraded"] = url.startswith('http://') and not explicit_scheme
                return result
            except Exception as e:
                last_error = _safe_err(e, 120)
                continue
        return {"ok": False, "url": target, "error": last_error}

    async def analyze_narrative(self, target, page=None):
        empty = analyze_narrative_text("")
        try:
            html = page.get('content') if page and page.get('ok') else None
            if not html:
                empty["geo_hint"] = _geo_hint(target)
                return empty
            soup = BeautifulSoup(html, 'html.parser')
            for tag in soup(["script", "style", "noscript", "nav", "footer", "header"]):
                tag.decompose()
            text = ' '.join(p.get_text(" ", strip=True) for p in soup.find_all(
                ['p', 'h1', 'h2', 'h3', 'article', 'blockquote']))[:20000]
            if len(text) < 100:
                empty["geo_hint"] = _geo_hint(target)
                return empty
            out = analyze_narrative_text(text)
            out["geo_hint"] = _geo_hint(target)
            return out
        except Exception as e:
            empty["geo_hint"] = _geo_hint(target)
            empty["error"] = _safe_err(e, 120)
            return empty

    async def passive_port_surface(self, target):
        if not self.shodan_key:
            return {"enabled": False, "note": "SHODAN_API_KEY no configurada"}
        try:
            ip, err = _resolve_public_ip(target)
            if err:
                return {"enabled": True, "ok": False, "error": err}
            resp = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                                params={"key": self.shodan_key}, timeout=15)
            if resp.status_code == 404:
                return {"enabled": True, "ok": True, "indexed": False, "ip": ip}
            if resp.status_code != 200:
                return {"enabled": True, "ok": False, "error": f"HTTP {resp.status_code}"}
            data = resp.json()
            return {"enabled": True, "ok": True, "indexed": True, "ip": ip,
                    "ports": data.get("ports", []), "org": data.get("org", "N/A"),
                    "os": data.get("os", "N/A"),
                    "vulns": list(data.get("vulns", []))[:20]}
        except Exception as e:
            return {"enabled": True, "ok": False, "error": _safe_err(e, 100)}

    async def analyze_ssl(self, target):
        domain = _api_domain(target)
        try:
            ok, why = _host_is_public(domain)
            if not ok:
                return {"ok": False, "error": f"Bloqueado (anti-SSRF): {why}"[:80]}
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=15) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    expires, days_left = None, None
                    not_after = cert.get('notAfter')
                    if not_after:
                        try:
                            exp = datetime.fromtimestamp(
                                ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
                            expires = exp.strftime('%Y-%m-%d')
                            days_left = (exp - datetime.now(timezone.utc)).days
                        except Exception:
                            pass
                    return {"ok": True, "version": ssock.version(),
                            "cipher": ssock.cipher()[0],
                            "issuer": dict(x[0] for x in cert.get('issuer', [])).get('commonName', 'N/A'),
                            "expires": expires or "N/A", "days_left": days_left}
        except Exception as e:
            return {"ok": False, "error": _safe_err(e, 80)}

    async def analyze_security_headers(self, page):
        headers = page.get('headers', {})
        result, vulnerabilities = {}, []
        passed = total = 0
        for header, info in self.security_headers_list.items():
            value = headers.get(header)
            total += 1
            if value:
                result[info['name']] = value[:80]
                passed += 1
            else:
                result[info['name']] = 'No configurado'
                vulnerabilities.append({'severity': info['severity'], 'title': info['title'],
                                       'detail': info['detail'],
                                       'recommendation': info['recommendation']})
        return {"headers": result, "vulnerabilities": vulnerabilities,
                "passed": passed, "total": total}

    async def analyze_cookies(self, page):
        headers = page.get('headers', {})
        cookies, vulnerabilities = [], []
        cookie_list = page.get('set_cookies') or []
        if not cookie_list:
            set_cookie = headers.get('Set-Cookie', '')
            if not set_cookie:
                return {"cookies": cookies, "vulnerabilities": vulnerabilities}
            cookie_list = re.split(r',(?=\s*[A-Za-z0-9_-]+\s*=)', set_cookie)
        for cookie_str in cookie_list:
            parts = [p.strip() for p in cookie_str.split(';')]
            if not parts or '=' not in parts[0]:
                continue
            name = parts[0].split('=', 1)[0].strip()
            attrs = [p.lower() for p in parts[1:]]
            httpOnly = 'httponly' in attrs
            secure = 'secure' in attrs
            same_site = 'No configurado'
            for a in parts[1:]:
                if a.lower().startswith('samesite='):
                    same_site = a.split('=', 1)[1].strip() or 'No configurado'
            cookies.append({"name": name, "httpOnly": httpOnly,
                            "secure": secure, "sameSite": same_site})
            if not httpOnly:
                vulnerabilities.append({'severity': 'Media',
                    'title': f'Cookie {name} sin HttpOnly',
                    'detail': 'Accesible por JavaScript',
                    'recommendation': 'session.cookie_httponly = On'})
            if not secure and page.get('final_url', page.get('url', '')).startswith('https://'):
                vulnerabilities.append({'severity': 'Media',
                    'title': f'Cookie {name} sin Secure en HTTPS',
                    'detail': 'Transmite por HTTP',
                    'recommendation': 'session.cookie_secure = On'})
            if same_site == 'No configurado':
                vulnerabilities.append({'severity': 'Baja',
                    'title': f'Cookie {name} sin SameSite',
                    'detail': 'Vulnerable a CSRF',
                    'recommendation': 'SameSite=Strict o Lax'})
            elif same_site.lower() == 'none' and not secure:
                vulnerabilities.append({'severity': 'Media',
                    'title': f'Cookie {name} SameSite=None sin Secure',
                    'detail': 'Rechazada por navegadores modernos',
                    'recommendation': 'SameSite=None con Secure'})
        return {"cookies": cookies, "vulnerabilities": vulnerabilities}

    async def analyze_suspicious_patterns(self, page):
        content = page.get('content', '')
        suspicious, suspicious_links = [], []
        if not content:
            return {"suspicious_patterns": suspicious, "suspicious_links": suspicious_links}
        MIN_HITS = 2
        for sig in self.suspicious_signatures:
            hits = list(re.finditer(sig['pattern'], content, re.IGNORECASE))
            if len(hits) < MIN_HITS:
                continue
            first = hits[0]
            start = max(0, first.start() - 50)
            end = min(len(content), first.end() + 50)
            context = content[start:end].replace('\n', ' ').replace('\r', '').strip()[:150]
            suspicious.append({'type': sig['type'], 'description': sig['desc'],
                               'severity': sig['severity'], 'context': context,
                               'occurrences': len(hits)})
        links = re.findall(r'(?:href|src)=["\']([^"\']+)["\']', content, re.IGNORECASE)
        for link in links:
            try:
                parsed = urlparse(link)
            except ValueError:
                continue
            host = (parsed.hostname or '').lower()
            path = (parsed.path or '').lower()
            if any(host.endswith(tld) for tld in self.suspicious_tlds) or \
               any(path.endswith(ext) for ext in ['.exe', '.scr', '.bat', '.apk']):
                suspicious_links.append(link[:300])
        return {"suspicious_patterns": suspicious,
                "suspicious_links": list(set(suspicious_links))[:20]}

    async def extract_iocs(self, page):
        content = page.get('content', '')
        iocs = {"ips": [], "domains": [], "urls": [], "hashes": []}
        if not content:
            return iocs
        try:
            for url in re.findall(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&()*+,;=%]+", content):
                url = url.rstrip(".,;)'\"")
                if len(url) > 12 and url not in iocs["urls"]:
                    iocs["urls"].append(url[:200])
                if len(iocs["urls"]) >= 200:
                    break
            for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content):
                try:
                    ip_obj = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if ip_obj.is_global and ip not in iocs["ips"]:
                    iocs["ips"].append(ip)
                if len(iocs["ips"]) >= 200:
                    break
            for dom in re.findall(
                    r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)'
                    r'+(?:com|net|org|ru|su|рф|io|info|biz|xyz|top|click|online|site|tk|ml|ga|cf)\b',
                    content, re.IGNORECASE):
                if dom.lower() not in iocs["domains"]:
                    iocs["domains"].append(dom.lower())
                if len(iocs["domains"]) >= 200:
                    break
            for h in re.findall(r'\b[a-fA-F0-9]{32}(?:[a-fA-F0-9]{8})?(?:[a-fA-F0-9]{24})?\b', content):
                if len(h) in (32, 40, 64) and h not in iocs["hashes"]:
                    iocs["hashes"].append(h.lower())
        except Exception:
            pass
        iocs["ips"] = iocs["ips"][:30]
        iocs["domains"] = iocs["domains"][:30]
        iocs["urls"] = iocs["urls"][:20]
        iocs["hashes"] = iocs["hashes"][:10]
        return iocs

    async def map_mitre_attack(self, page, suspicious_data, vt_data, gsb_data, urlhaus_data):
        content = page.get('content', '') if page else ''
        techniques = []
        seen = set()

        def add(tech_id, name, tactic, evidence):
            if tech_id not in seen:
                seen.add(tech_id)
                techniques.append({"id": tech_id, "name": name, "tactic": tactic,
                                   "evidence": evidence[:120]})

        for m in (suspicious_data or {}).get('suspicious_patterns', []):
            t = m.get('type', '')
            tl = t.lower()
            if 'base64' in tl or 'obfuscaci' in tl or 'ofuscaci' in tl:
                add("T1027", "Obfuscated Files or Information", "Defense Evasion",
                    f"Firma: {t} — {m.get('context', '')[:80]}")
            if 'IFrame' in t:
                add("T1189", "Drive-by Compromise", "Initial Access",
                    f"iframe oculto — {m.get('context', '')[:80]}")
            if 'Cryptominer' in t:
                add("T1496", "Resource Hijacking", "Impact", f"Minería: {t}")
            if 'EXE' in t:
                add("T1204.002", "User Execution: Malicious File", "Execution",
                    "Enlace a .exe")
        if 'wp-admin' in content or 'wp-login' in content:
            add("T1190", "Exploit Public-Facing Application", "Initial Access",
                "Rutas WP expuestas")
        if (urlhaus_data or {}).get('ok') and urlhaus_data.get('detected'):
            add("T1071.001", "Web Protocols (C2 HTTP/S)", "Command and Control",
                f"URLHaus: {urlhaus_data.get('threat', 'malware')}")
        if (vt_data or {}).get('malicious', 0) > 0:
            add("T1583.001", "Acquire Infrastructure: Domains", "Resource Development",
                f"VT: {vt_data['malicious']} motores")
        if (gsb_data or {}).get('detected'):
            add("T1566.002", "Phishing: Spearphishing Link", "Initial Access",
                f"GSB: {', '.join(gsb_data.get('matches') or [])}")
        return techniques

    async def assess_c2(self, vt_data, gsb_data, urlhaus_data, iocs):
        signals, score = [], 0
        if (urlhaus_data or {}).get('ok') and urlhaus_data.get('detected'):
            signals.append(f"URLHaus lista el host ({urlhaus_data.get('threat')}, "
                           f"{urlhaus_data.get('urls_count', '?')} URLs)")
            score += 50
        if (vt_data or {}).get('malicious', 0) > 0:
            signals.append(f"VT: {vt_data['malicious']} motores malicioso")
            score += min(30, vt_data['malicious'] * 5)
        elif (vt_data or {}).get('suspicious', 0) > 0:
            signals.append(f"VT: {vt_data['suspicious']} motores sospechoso")
            score += 10
        if (gsb_data or {}).get('detected'):
            signals.append(f"GSB: {', '.join(gsb_data.get('matches') or [])}")
            score += 30
        n_iocs = len(iocs.get('ips', [])) + len(iocs.get('urls', []))
        if n_iocs >= 10:
            signals.append(f"{n_iocs} IOCs en HTML")
            score += 10
        score = min(100, score)
        if score >= 60:
            level = "C2 PROBABLE"
        elif score >= 30:
            level = "INDICIOS DE C2"
        elif score > 0:
            level = "SIN EVIDENCIA CLARA"
        else:
            level = "SIN EVIDENCIA"
        return {"score": score, "level": level, "signals": signals}

    async def detect_technologies(self, page):
        headers = page.get('headers', {})
        content = page.get('content', '')
        techs = []
        if 'Server' in headers:
            techs.append(f"Servidor: {headers['Server']}")
        if 'X-Powered-By' in headers:
            techs.append(f"Powered By: {headers['X-Powered-By']}")
        if 'PHPSESSID' in str(headers):
            techs.append("PHP")
        if 'X-AspNet-Version' in headers:
            techs.append("ASP.NET")
        if 'wp-content' in content or 'wp-includes' in content:
            techs.append("WordPress")
        if 'Drupal' in content:
            techs.append("Drupal")
        if 'Joomla' in content:
            techs.append("Joomla")
        return techs

    async def analyze_virustotal(self, target):
        if not self.vt_api_key:
            return {"enabled": False, "error": "VT_API_KEY no configurada"}
        host = _api_domain(target)
        if not host:
            return {"enabled": True, "ok": False, "error": "Objetivo inválido"}
        kind = "ip_addresses" if _is_ip(host) else "domains"
        url = f"https://www.virustotal.com/api/v3/{kind}/{quote(host, safe='')}"
        console.print(f"🔬 [VT] Consultando {url}", markup=False)
        try:
            headers = {"x-apikey": self.vt_api_key}
            r = requests.get(url, headers=headers, timeout=15)
            console.print(f"🔬 [VT] HTTP {r.status_code}", markup=False)
            if r.status_code == 401:
                return {"enabled": True, "ok": False, "error": "API key inválida (401)"}
            if r.status_code == 403:
                return {"enabled": True, "ok": False, "error": "Acceso prohibido (403)"}
            if r.status_code == 429:
                return {"enabled": True, "ok": False, "error": "Cuota agotada (429)"}
            if r.status_code == 404:
                return {"enabled": True, "ok": True, "not_found": True,
                        "malicious": 0, "suspicious": 0, "harmless": 0,
                        "undetected": 0, "reputation": 0, "flagged_by": []}
            if r.status_code != 200:
                return {"enabled": True, "ok": False, "error": f"HTTP {r.status_code}"}
            data = r.json()
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            results = attrs.get('last_analysis_results', {})
            flagged = sorted([e for e, v in results.items()
                              if v.get('category') in ('malicious', 'suspicious')])
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            console.print(f"🔬 [VT] malicious={malicious} suspicious={suspicious} "
                          f"harmless={stats.get('harmless', 0)} "
                          f"undetected={stats.get('undetected', 0)}", markup=False)
            return {"enabled": True, "ok": True,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": stats.get('harmless', 0),
                    "undetected": stats.get('undetected', 0),
                    "reputation": attrs.get('reputation', 0),
                    "flagged_by": flagged[:15],
                    "categories": list(attrs.get('categories', {}).values())[:5]}
        except requests.exceptions.Timeout:
            return {"enabled": True, "ok": False, "error": "Timeout (15s)"}
        except requests.exceptions.ConnectionError as e:
            return {"enabled": True, "ok": False,
                    "error": f"Error conexión: {_safe_err(e, 80)}"}
        except Exception as e:
            return {"enabled": True, "ok": False,
                    "error": f"{type(e).__name__}: {_safe_err(e, 120)}"}

    async def analyze_google_safe_browsing(self, target):
        if not self.gsb_key:
            return {"enabled": False}
        url = target if target.startswith('http') else f"https://{target}"
        body = {"client": {"clientId": APP_NAME, "clientVersion": APP_VERSION},
                "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                               "platformTypes": ["ANY_PLATFORM"],
                               "threatEntryTypes": ["URL"],
                               "threatEntries": [{"url": url}]}}
        try:
            resp = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                                 params={"key": self.gsb_key}, json=body, timeout=15)
            resp.raise_for_status()
            matches = resp.json().get('matches', [])
            return {"enabled": True, "ok": True, "detected": bool(matches),
                    "matches": [m.get('threatType') for m in matches] or None}
        except Exception as e:
            return {"enabled": True, "ok": False, "error": _safe_err(e, 100)}

    async def analyze_urlhaus(self, target):
        try:
            d = _api_domain(target)
            headers = {"User-Agent": f"{APP_NAME}/{APP_VERSION}"}
            if self.urlhaus_auth_key:
                headers["Auth-Key"] = self.urlhaus_auth_key
            resp = requests.post("https://urlhaus-api.abuse.ch/v1/host/",
                                 data={"host": d}, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            if data.get("query_status") == "no_result":
                return {"enabled": True, "ok": True, "detected": False}
            return {"enabled": True, "ok": True, "detected": True,
                    "threat": data.get("query_status"),
                    "reference": data.get("urlhaus_reference"),
                    "urls_count": len(data.get("urls", []))}
        except requests.exceptions.HTTPError as e:
            if "401" in str(e):
                return {"enabled": True, "ok": False, "error": "URLHaus requiere Auth-Key"}
            return {"enabled": True, "ok": False, "error": _safe_err(e, 100)}
        except Exception as e:
            return {"enabled": True, "ok": False, "error": _safe_err(e, 100)}

    async def web_security_audit(self, target, page):
        ssl_data = await _guard(self.analyze_ssl(target), {"ok": False})
        if not page or not page.get('ok'):
            return {"reachable": False,
                    "error": page.get('error', 'No se pudo acceder') if page else 'Sin datos',
                    "ssl": ssl_data, "risk_score": 0, "risk_level": "N/A"}

        headers_data = await _guard(self.analyze_security_headers(page),
                                    {"headers": {}, "vulnerabilities": [],
                                     "passed": 0, "total": 0})
        cookies_data = await _guard(self.analyze_cookies(page),
                                    {"cookies": [], "vulnerabilities": []})
        suspicious_data = await _guard(self.analyze_suspicious_patterns(page),
                                       {"suspicious_patterns": [], "suspicious_links": []})
        techs = await _guard(self.detect_technologies(page), [])
        vt_data = await _guard(self.analyze_virustotal(target), {"enabled": True, "ok": False})
        gsb_data = await _guard(self.analyze_google_safe_browsing(target), {"enabled": True, "ok": False})
        urlhaus_data = await _guard(self.analyze_urlhaus(target), {"enabled": True, "ok": False})
        iocs = await _guard(self.extract_iocs(page), {"ips": [], "domains": [],
                                                      "urls": [], "hashes": []})
        mitre = await _guard(self.map_mitre_attack(page, suspicious_data, vt_data,
                                                    gsb_data, urlhaus_data), [])
        c2 = await _guard(self.assess_c2(vt_data, gsb_data, urlhaus_data, iocs),
                          {"score": 0, "level": "SIN EVIDENCIA", "signals": []})

        vulnerabilities = list(headers_data['vulnerabilities']) + \
                          list(cookies_data['vulnerabilities'])

        if ssl_data.get('ok'):
            if ssl_data.get('version') in ('SSLv3', 'TLSv1', 'TLSv1.1'):
                vulnerabilities.append({'severity': 'Alta',
                    'title': f"TLS obsoleto ({ssl_data.get('version')})",
                    'detail': 'Versiones <1.2 tienen ataques conocidos',
                    'recommendation': 'Solo TLS 1.2 y 1.3'})
            dl = ssl_data.get('days_left')
            if dl is not None and dl <= 14:
                vulnerabilities.append({'severity': 'Media',
                    'title': f'Certificado caduca en {dl} día(s)',
                    'detail': f"Expira {ssl_data.get('expires')}",
                    'recommendation': 'Renovar (ACME)'})
        final_url = page.get('final_url') or ''
        if final_url.startswith('http://'):
            vulnerabilities.append({'severity': 'Alta', 'title': 'Sitio sin HTTPS',
                'detail': 'Tráfico en claro',
                'recommendation': 'HTTPS + 301 desde HTTP'})
        hdrs = page.get('headers', {})
        for hname in ('Server', 'X-Powered-By'):
            val = hdrs.get(hname, '')
            if val and re.search(r'\d+\.\d+', val):
                vulnerabilities.append({'severity': 'Baja',
                    'title': f'Divulgación de versión en {hname}',
                    'detail': val[:60],
                    'recommendation': 'ServerTokens Prod / expose_php=Off'})

        score = (headers_data['passed'] / headers_data['total'] * 100) \
                if headers_data['total'] else 100.0
        high_suspicious = sum(1 for m in suspicious_data['suspicious_patterns']
                              if m['severity'] == 'Alta')
        score -= (high_suspicious * 15)
        high_vuln = sum(1 for v in vulnerabilities if v['severity'] == 'Alta')
        medium_vuln = sum(1 for v in vulnerabilities if v['severity'] == 'Media')
        low_vuln = sum(1 for v in vulnerabilities if v['severity'] == 'Baja')
        score -= (high_vuln * 15) + (medium_vuln * 5) + (low_vuln * 2)
        if vt_data.get('malicious', 0) > 0 or gsb_data.get('detected') or urlhaus_data.get('detected'):
            score -= 30
        elif vt_data.get('suspicious', 0) > 0:
            score -= 10
        score = max(0, min(100, score))
        if score <= 30:
            level = "CRÍTICO"
        elif score <= 50:
            level = "ALTO"
        elif score <= 70:
            level = "MEDIO"
        else:
            level = "BAJO"

        return {"reachable": True, "status_code": page.get('status_code'),
                "http": {"status_code": page.get('status_code'),
                         "time": page.get('time'), "size": page.get('size'),
                         "redirects": page.get('redirects'),
                         "final_url": page.get('final_url'),
                         "downgraded": page.get('downgraded', False),
                         "truncated": page.get('truncated', False)},
                "ssl": ssl_data, "security_headers": headers_data['headers'],
                "cookies": cookies_data['cookies'],
                "suspicious_patterns": suspicious_data['suspicious_patterns'],
                "suspicious_links": suspicious_data['suspicious_links'],
                "technologies": techs, "virustotal": vt_data,
                "safe_browsing": gsb_data, "urlhaus": urlhaus_data,
                "iocs": iocs, "mitre_attack": mitre, "c2_assessment": c2,
                "vulnerabilities": vulnerabilities,
                "risk_score": round(score, 1), "risk_level": level}

    async def check_certificate_transparency(self, domain):
        d = _api_domain(domain)
        try:
            resp = requests.get("https://crt.sh/", params={"q": f"%.{d}", "output": "json"},
                                timeout=(5, 25))
            if resp.status_code != 200 or not resp.text.strip():
                return {"ok": False, "error": f"HTTP {resp.status_code}", "subdomains": []}
            data = resp.json()
            subdomains, issuers = set(), set()
            for entry in data:
                for n in entry.get('name_value', '').split('\n'):
                    n = n.strip().lower()
                    if n and not n.startswith('*'):
                        subdomains.add(n)
                if entry.get('issuer_name'):
                    issuers.add(entry['issuer_name'].split(',')[0])
            return {"ok": True, "subdomains": sorted(subdomains)[:100],
                    "total_subdomains": len(subdomains),
                    "certificate_count": len(data), "issuers": sorted(issuers)}
        except Exception as e:
            return {"ok": False, "error": _safe_err(e, 100), "subdomains": []}

    async def favicon_fingerprint(self, target):
        try:
            import mmh3
            import base64 as b64
            url = target if target.startswith('http') else f"https://{target}"
            parsed = urlparse(url)
            ok, why = _host_is_public(_extract_host(url))
            if not ok:
                return {"ok": False, "error": f"Bloqueado: {why}"[:100]}
            base = f"{parsed.scheme}://{parsed.netloc}"
            resp = requests.get(f"{base}/favicon.ico", timeout=8, verify=True,
                                allow_redirects=False, stream=True)
            content = b""
            if resp.status_code == 200:
                content = resp.raw.read(1_000_000, decode_content=True)
            resp.close()
            if resp.status_code != 200 or not content:
                return {"ok": False, "error": "Sin favicon.ico"}
            favicon_hash = mmh3.hash(b64.encodebytes(content))
            return {"ok": True, "hash": favicon_hash,
                    "shodan_query": f"http.favicon.hash:{favicon_hash}"}
        except ImportError:
            return {"ok": False, "error": "Falta mmh3 (pip install mmh3)"}
        except Exception as e:
            return {"ok": False, "error": _safe_err(e, 100)}

    async def check_wayback_machine(self, target):
        d = _api_domain(target)
        for attempt in (1, 2):
            try:
                resp = requests.get("https://archive.org/wayback/available",
                                    params={"url": d}, timeout=15)
                if resp.status_code != 200:
                    if attempt == 2:
                        return {"ok": False, "error": f"HTTP {resp.status_code}"}
                    continue
                ct = resp.headers.get('Content-Type', '')
                if 'json' not in ct.lower():
                    if attempt == 2:
                        return {"ok": False, "error": "Respuesta no JSON"}
                    continue
                data = resp.json()
                snap = data.get('archived_snapshots', {}).get('closest')
                if not snap:
                    return {"ok": True, "archived": False}
                return {"ok": True, "archived": True,
                        "first_seen_hint": snap.get('timestamp', 'N/A'),
                        "snapshot_url": snap.get('url', 'N/A'),
                        "status": snap.get('status', 'N/A')}
            except Exception as e:
                if attempt == 2:
                    return {"ok": False, "error": _safe_err(e, 100)}
        return {"ok": False, "error": "Wayback no disponible"}

    async def analyze_dns_extended(self, domain):
        d = _api_domain(domain)
        result = {"mx": [], "spf": None, "dmarc": None}
        try:
            import dns.resolver
        except ImportError:
            result["ok"] = False
            result["error"] = "Falta dnspython (pip install dnspython)"
            return result
        try:
            mx_records = dns.resolver.resolve(d, 'MX', lifetime=8)
            result["mx"] = sorted([str(r.exchange).rstrip('.') for r in mx_records])
        except Exception:
            pass
        try:
            for r in dns.resolver.resolve(d, 'TXT', lifetime=8):
                txt = ''.join(p.decode() if isinstance(p, bytes) else p for p in r.strings)
                if txt.lower().startswith('v=spf1'):
                    result["spf"] = txt
        except Exception:
            pass
        try:
            for r in dns.resolver.resolve(f'_dmarc.{d}', 'TXT', lifetime=8):
                txt = ''.join(p.decode() if isinstance(p, bytes) else p for p in r.strings)
                if txt.lower().startswith('v=dmarc1'):
                    result["dmarc"] = txt
        except Exception:
            pass
        result["ok"] = True
        return result

    async def check_abuseipdb(self, target):
        if not self.abuseipdb_key:
            return {"enabled": False}
        try:
            ip, err = _resolve_public_ip(target)
            if err:
                return {"enabled": True, "ok": False, "error": err}
            headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
            resp = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers,
                                params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10)
            if resp.status_code != 200:
                return {"enabled": True, "ok": False, "error": f"HTTP {resp.status_code}"}
            data = resp.json().get("data", {})
            return {"enabled": True, "ok": True,
                    "abuse_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", "N/A"),
                    "is_tor": data.get("isTor", False)}
        except Exception as e:
            return {"enabled": True, "ok": False, "error": _safe_err(e, 100)}

    async def check_greynoise(self, target):
        if not self.greynoise_key:
            return {"enabled": False}
        try:
            ip, err = _resolve_public_ip(target)
            if err:
                return {"enabled": True, "ok": False, "error": err}
            headers = {"key": self.greynoise_key, "Accept": "application/json"}
            resp = requests.get(f"https://api.greynoise.io/v3/community/{ip}",
                                headers=headers, timeout=10)
            if resp.status_code == 404:
                return {"enabled": True, "ok": True, "seen": False}
            if resp.status_code != 200:
                return {"enabled": True, "ok": False, "error": f"HTTP {resp.status_code}"}
            data = resp.json()
            return {"enabled": True, "ok": True, "seen": True,
                    "classification": data.get("classification", "N/A"),
                    "name": data.get("name", "N/A"),
                    "noise": data.get("noise", False), "riot": data.get("riot", False)}
        except Exception as e:
            return {"enabled": True, "ok": False, "error": _safe_err(e, 100)}

    async def osint_scan(self, target):
        domain = _extract_host(target) or target
        return {
            "certificate_transparency": await _guard(
                self.check_certificate_transparency(domain),
                {"ok": False, "subdomains": []}),
            "favicon": await _guard(self.favicon_fingerprint(target), {"ok": False}),
            "wayback": await _guard(self.check_wayback_machine(target), {"ok": False}),
            "dns_extended": await _guard(self.analyze_dns_extended(domain), {"ok": False}),
            "abuseipdb": await _guard(self.check_abuseipdb(target),
                                     {"enabled": True, "ok": False}),
            "greynoise": await _guard(self.check_greynoise(target),
                                     {"enabled": True, "ok": False}),
            "shodan_passive": await _guard(self.passive_port_surface(target),
                                           {"enabled": True, "ok": False}),
        }

    async def send_telegram_alert(self, message):
        if not self.telegram_token or not self.telegram_chat_id:
            return {"enabled": False}
        try:
            resp = requests.post(
                f"https://api.telegram.org/bot{self.telegram_token}/sendMessage",
                data={"chat_id": self.telegram_chat_id, "text": message}, timeout=10)
            return {"enabled": True, "ok": resp.status_code == 200}
        except Exception as e:
            return {"enabled": True, "ok": False, "error": _safe_err(e, 100)}

    async def detect_cyber_attack_patterns(self, target, geo=None, shodan=None,
                                            prop=None, page=None):
        patterns = []
        shodan = shodan if shodan is not None else await self.passive_port_surface(target)
        if shodan.get('enabled') and shodan.get('ok') and shodan.get('indexed'):
            dangerous = {22: "high", 445: "critical", 3389: "high", 3306: "medium",
                         5432: "medium", 6379: "medium", 27017: "medium", 23: "high",
                         5900: "high", 21: "medium"}
            for port in shodan.get('ports', []):
                if port in dangerous:
                    patterns.append({"type": "port",
                                     "name": f"{EMOJIS['ports']} Puerto {port} expuesto (Shodan pasivo)",
                                     "severity": dangerous[port],
                                     "details": f"Puerto {port} visto por Shodan"})
            if shodan.get('vulns'):
                patterns.append({"type": "vuln",
                                 "name": f"{EMOJIS['critical']} {len(shodan['vulns'])} CVEs (Shodan)",
                                 "severity": "high",
                                 "details": ", ".join(shodan['vulns'][:5])})

        blacklist_info = self.reputation_analyzer.check_blacklist(target)
        if blacklist_info:
            patterns.append({"type": "blacklist",
                             "name": f"{EMOJIS['critical']} Objetivo en lista negra",
                             "severity": "critical",
                             "details": f"Razón: {blacklist_info.get('reason', 'N/A')}"})

        whitelist_info = self.reputation_analyzer.check_whitelist(target)
        if whitelist_info:
            patterns.append({"type": "whitelist",
                             "name": f"{EMOJIS['safe']} Objetivo en lista blanca",
                             "severity": "safe",
                             "details": f"Razón: {whitelist_info.get('reason', 'N/A')}"})

        risk_level = "INOCUO"
        severities = [p['severity'] for p in patterns if p['severity'] != 'safe']
        if not severities:
            risk_level = "INOCUO"
        elif 'critical' in severities:
            risk_level = "CRITICO"
        elif severities.count('high') >= 3:
            risk_level = "CRITICO"
        elif severities.count('high') >= 2:
            risk_level = "ALTO"
        elif 'high' in severities:
            risk_level = "MEDIO"
        elif 'medium' in severities:
            risk_level = "BAJO"
        elif 'low' in severities:
            risk_level = "MUY BAJO"

        risk_score = 0
        for p in patterns:
            if p['severity'] == 'critical':
                risk_score += 30
            elif p['severity'] == 'high':
                risk_score += 20
            elif p['severity'] == 'medium':
                risk_score += 10
            elif p['severity'] == 'low':
                risk_score += 5
        risk_score = min(risk_score, 100)

        return {"patterns": patterns, "risk_level": risk_level, "risk_score": risk_score}

    async def full_scan(self, target, include_osint=True):
        ok, why = validate_target(target)
        if not ok:
            raise ValueError(f"Objetivo inválido: {why}")
        self.scan_count += 1
        page = await self.fetch_page(target)
        whois_data = await self.get_whois(target)
        geo_data = await self.get_geolocation(target)
        narrative_data = await self.analyze_narrative(target, page=page)
        shodan = await self.passive_port_surface(target)
        attack = await self.detect_cyber_attack_patterns(target, geo=geo_data,
                                                          shodan=shodan, page=page)
        web_security = await self.web_security_audit(target, page)
        osint = await self.osint_scan(target) if include_osint else {}

        result = {"target": target, "timestamp": datetime.now().isoformat(),
                  "scan_id": f"SCAN-{self.scan_count:04d}",
                  "whois": whois_data, "geolocation": geo_data,
                  "narrative": narrative_data,
                  "shodan_passive": shodan,
                  "attack_patterns": attack,
                  "risk_level": attack['risk_level'],
                  "risk_score": attack['risk_score'],
                  "web_security": web_security, "osint": osint,
                  "blacklisted": bool(self.reputation_analyzer.check_blacklist(target)),
                  "whitelisted": bool(self.reputation_analyzer.check_whitelist(target))}

        logger.log_scan(target, result)
        logger.log_event(
            target,
            "CRITICAL" if attack['risk_level'] == "CRITICO" else
            "WARNING" if attack['risk_level'] in ["ALTO", "MEDIO"] else "INFO",
            f"{EMOJIS['scan']} Escaneo completado. Riesgo técnico: {attack['risk_level']} | "
            f"Score: {attack['risk_score']}/100 | Web: {web_security.get('risk_level', 'N/A')}")

        if attack['risk_level'] == "CRITICO" or web_security.get('risk_level') == "CRÍTICO":
            await self.send_telegram_alert(
                f"🚨 {APP_NAME} — ALERTA CRÍTICA (técnica)\n"
                f"Objetivo: {target}\n"
                f"Riesgo técnico: {attack['risk_level']} ({attack['risk_score']}/100)\n"
                f"Web security: {web_security.get('risk_level', 'N/A')} "
                f"({web_security.get('risk_score', 0)}/100)")
        return result

    

def show_banner(scanner):
    console.clear()
    stats = logger.get_stats()
    banner_text = f"""
╔══════════════════════════════════════════════════════╗
║  🌀 CIRCINUSWATCH v{APP_VERSION} — Passive OSINT          ║
║  🛡 Web Security Audit + Narrative Framing            ║
║  👤 Author: Condor2026 | Modo: {scanner.mode}         ║
╠══════════════════════════════════════════════════════╣
║  ⚖️ 100% PASIVO: puertos solo vía índice Shodan      ║
║  🔒 Sin escaneo activo. Sin claves en el código.     ║
║  🧱 Anti-SSRF · descarga acotada · logs atómicos     ║
║  🗣 Análisis narrativo SIMÉTRICO (no veredicto)      ║
╚══════════════════════════════════════════════════════╝

📊 ESTADÍSTICAS EN VIVO:
{EMOJIS['critical']} Amenazas críticas: {stats['critical']:>3}
{EMOJIS['warning']} Alertas:          {stats['warning']:>3}
{EMOJIS['info']} Eventos normales:   {stats['info']:>3}
🔍 Total escaneos:     {scanner.scan_count:>3}
🎯 Objetivos únicos:   {stats.get('unique_targets', 0):>3}
📈 Tasa de amenazas:   {stats.get('threat_rate', 0):.1%}
⭐ Reputación promedio: {stats.get('avg_reputation', 0):>+.1f}
"""
    console.print(Panel(banner_text, border_style="red",
                        title="🔥 SISTEMA ACTIVO", title_align="center"), markup=False)


def show_menu():
    menu = Table(box=box.ROUNDED, border_style="cyan",
                 title="📋 MENÚ PRINCIPAL", title_style="bold yellow")
    menu.add_column("🔢", style="bold yellow", width=6)
    menu.add_column("⚡ Función", style="bold white", width=22)
    menu.add_column("📝 Descripción", style="dim", width=45)
    menu.add_row("1", "🎯 Escanear objetivo", "OSINT pasivo + auditoría web + encuadre narrativo")
    menu.add_row("2", "📊 Dashboard web", "Panel de control con gráficos")
    menu.add_row("3", "📜 Ver logs", "Historial de eventos")
    menu.add_row("4", "📦 Escaneo masivo", "Analizar lista de dominios")
    menu.add_row("5", "📈 Estadísticas", "Métricas detalladas")
    menu.add_row("6", "🗑 Limpiar logs", "Eliminar historial")
    menu.add_row("7", "⛔ Gestión de listas", "Blacklist/Whitelist")
    menu.add_row("8", "💾 Backup", "Crear copia de seguridad")
    menu.add_row("9", "📤 Exportar reporte", "Generar informe detallado")
    menu.add_row("10", "🕵 OSINT extra", "crt.sh, favicon, Wayback, DNS")
    menu.add_row("11", "👁 Vigilancia periódica", "Gestionar y correr watchlist")
    menu.add_row("12", "📤 Exportar STIX", "Bundle STIX del último escaneo")
    menu.add_row("0", "❌ Salir", "Cerrar herramienta")
    console.print(menu, markup=False)


def wait_for_enter(message="\n⌨ Presiona Enter para continuar..."):
    Prompt.ask(message)


def render_osint_table(target, osint):
    if not osint:
        return
    osint_table = Table(title=f"🕵 OSINT — {target.upper()}",
                        box=box.DOUBLE_EDGE, title_style="bold magenta")
    osint_table.add_column("📌 Fuente", style="bold yellow", width=25)
    osint_table.add_column("📋 Resultado", style="white", width=55)

    ct = osint.get('certificate_transparency', {})
    if ct.get('ok'):
        osint_table.add_row("📜 Certificate Transparency",
                            f"{ct.get('total_subdomains', 0)} subdominios | "
                            f"{ct.get('certificate_count', 0)} certificados | "
                            f"Emisores: {', '.join(ct.get('issuers', [])[:3]) or 'N/A'}")
        subs = ct.get('subdomains', [])
        if subs:
            osint_table.add_row("   ↳ Subdominios",
                                ", ".join(subs[:8]) +
                                (f" ... (+{len(subs)-8})" if len(subs) > 8 else ""))
    else:
        osint_table.add_row("📜 Certificate Transparency",
                            f"⚠ {ct.get('error', 'Sin datos')}")

    fav = osint.get('favicon', {})
    if fav.get('ok'):
        osint_table.add_row("🖼 Favicon hash",
                            f"{fav['hash']} — Shodan: {fav['shodan_query']}")
    else:
        osint_table.add_row("🖼 Favicon hash", f"⚠ {fav.get('error', 'Sin datos')}")

    wb = osint.get('wayback', {})
    if wb.get('ok'):
        if wb.get('archived'):
            osint_table.add_row("🕰 Wayback Machine",
                                f"Archivado — snapshot: {wb.get('first_seen_hint', 'N/A')}")
        else:
            osint_table.add_row("🕰 Wayback Machine", "Sin snapshots conocidos")
    else:
        osint_table.add_row("🕰 Wayback Machine", f"⚠ {wb.get('error', 'Sin datos')}")

    dns_ext = osint.get('dns_extended', {})
    if dns_ext.get('ok'):
        mx = ", ".join(dns_ext.get('mx', [])) or "Sin MX"
        spf = "✅" if dns_ext.get('spf') else "❌"
        dmarc = "✅" if dns_ext.get('dmarc') else "❌"
        osint_table.add_row("📧 DNS extendido", f"MX: {mx} | SPF: {spf} | DMARC: {dmarc}")
    else:
        osint_table.add_row("📧 DNS extendido", f"⚠ {dns_ext.get('error', 'Sin datos')}")

    sh = osint.get('shodan_passive', {})
    if sh.get('enabled'):
        if sh.get('ok') and sh.get('indexed'):
            osint_table.add_row("🔭 Shodan (pasivo)",
                                f"Puertos: {sh.get('ports', [])} | Org: {sh.get('org', 'N/A')} | "
                                f"Vulns: {len(sh.get('vulns', []))}")
        elif sh.get('ok'):
            osint_table.add_row("🔭 Shodan (pasivo)", "No indexado")
        else:
            osint_table.add_row("🔭 Shodan (pasivo)", f"⚠ {sh.get('error', 'N/A')}")
    else:
        osint_table.add_row("🔭 Shodan (pasivo)", "Deshabilitado (falta SHODAN_API_KEY)")

    abuse = osint.get('abuseipdb', {})
    if abuse.get('enabled'):
        if abuse.get('ok'):
            osint_table.add_row("🚫 AbuseIPDB",
                                f"Score: {abuse.get('abuse_score', 0)}/100 | "
                                f"Reportes: {abuse.get('total_reports', 0)}")
        else:
            osint_table.add_row("🚫 AbuseIPDB", f"⚠ {abuse.get('error', 'N/A')}")
    else:
        osint_table.add_row("🚫 AbuseIPDB", "Deshabilitado (falta ABUSEIPDB_API_KEY)")

    gn = osint.get('greynoise', {})
    if gn.get('enabled'):
        if gn.get('ok') and gn.get('seen'):
            osint_table.add_row("🌫 GreyNoise",
                                f"{gn.get('classification', 'N/A')} — {gn.get('name', 'N/A')}")
        elif gn.get('ok'):
            osint_table.add_row("🌫 GreyNoise", "No visto escaneando masivamente")
        else:
            osint_table.add_row("🌫 GreyNoise", f"⚠ {gn.get('error', 'N/A')}")
    else:
        osint_table.add_row("🌫 GreyNoise", "Deshabilitado (falta GREYNOISE_API_KEY)")

    console.print(osint_table, markup=False)


async def scan_target(scanner):
    console.print("\n🎯 ESCANEO INTELIGENTE", markup=False)
    console.print("📝 Ingresa IP, dominio o URL para analizar", markup=False)
    target = Prompt.ask("🌐 Objetivo").strip()
    if not target:
        return
    ok, why = validate_target(target)
    if not ok:
        console.print(f"❌ Objetivo inválido: {why}", markup=False)
        wait_for_enter()
        return

    console.print(f"\n🔍 Escaneando {target}...", markup=False)

    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TimeRemainingColumn(), console=console) as p:
        task = p.add_task("🔄 Escaneando...", total=100)

        p.update(task, description="🌐 Descargando página...", advance=5)
        page = await scanner.fetch_page(target)
        p.update(task, advance=5)

        p.update(task, description="📋 Obteniendo WHOIS...", advance=10)
        whois_data = await scanner.get_whois(target)
        p.update(task, advance=5)

        p.update(task, description="🌍 Geolocalizando...", advance=10)
        geo_data = await scanner.get_geolocation(target)
        p.update(task, advance=5)

        p.update(task, description="🗣 Analizando encuadre narrativo...", advance=10)
        narrative_data = await scanner.analyze_narrative(target, page=page)
        p.update(task, advance=10)

        p.update(task, description="🔭 Shodan pasivo...", advance=10)
        shodan = await scanner.passive_port_surface(target)
        p.update(task, advance=5)

        p.update(task, description="🛡 Detectando patrones...", advance=10)
        attack = await scanner.detect_cyber_attack_patterns(
            target, geo=geo_data, shodan=shodan, page=page)
        p.update(task, advance=5)

        p.update(task, description="🔒 Auditoría de seguridad web...", advance=10)
        web_security = await scanner.web_security_audit(target, page)
        p.update(task, advance=5)

        p.update(task, description="🕵 OSINT...", advance=5)
        osint = await scanner.osint_scan(target)
        p.update(task, advance=5)

    scanner.scan_count += 1
    scan_result = {"target": target, "timestamp": datetime.now().isoformat(),
                   "scan_id": f"SCAN-{scanner.scan_count:04d}",
                   "whois": whois_data, "geolocation": geo_data,
                   "narrative": narrative_data,
                   "shodan_passive": shodan, "attack_patterns": attack,
                   "risk_level": attack['risk_level'], "risk_score": attack['risk_score'],
                   "web_security": web_security, "osint": osint,
                   "blacklisted": bool(scanner.reputation_analyzer.check_blacklist(target)),
                   "whitelisted": bool(scanner.reputation_analyzer.check_whitelist(target))}
    logger.log_scan(target, scan_result)
    logger.log_event(
        target,
        "CRITICAL" if attack['risk_level'] == "CRITICO" else
        "WARNING" if attack['risk_level'] in ["ALTO", "MEDIO"] else "INFO",
        f"{EMOJIS['scan']} Escaneo completado. Riesgo técnico: {attack['risk_level']} | "
        f"Score: {attack['risk_score']}/100 | Web: {web_security.get('risk_level', 'N/A')}")

    table = Table(title=f"📊 RESULTADOS PARA {target.upper()}",
                  box=box.DOUBLE_EDGE, title_style="bold cyan")
    table.add_column("📌 Métrica", style="bold yellow", width=22)
    table.add_column("📋 Valor", style="white", width=60)

    table.add_row("🌍 País", geo_data.get("country", "Desconocido"))
    table.add_row("🏙 Ciudad", geo_data.get("city", "N/A"))
    table.add_row("🏢 ISP", geo_data.get("org", "N/A"))
    table.add_row("🖥 IP", geo_data.get("ip", "N/A"))
    table.add_row("📅 Fecha creación", whois_data.get("creation_date", "N/A"))
    table.add_row("📋 Registrador", whois_data.get("registrar", "N/A"))
    table.add_row("🗣 Marcadores narrativos", str(narrative_data.get('total_markers', 0)))
    table.add_row("🗣 Intensidad de encuadre", f"{narrative_data.get('framing_intensity', 0):.2f}")
    cats = narrative_data.get('categories', {})
    table.add_row("🗣 Categorías", ", ".join(f"{k}:{v}" for k, v in cats.items()) or "Ninguna")
    bal = narrative_data.get('balance', {})
    table.add_row("🗣 Balance direccional",
                  ", ".join(f"{k}:{v}" for k, v in bal.items()) or "Sin marcadores direccionales")

    for p_ in attack['patterns']:
        if p_['severity'] == 'safe':
            color = "green"
        elif p_['severity'] == 'critical':
            color = "red"
        elif p_['severity'] == 'high':
            color = "yellow"
        elif p_['severity'] == 'medium':
            color = "orange1"
        else:
            color = "cyan"
        table.add_row(f"📌 Patrón {p_['type']}", Text(p_['name'], style=color))
        if p_.get('details'):
            table.add_row("", Text(p_['details'], style="dim"))

    risk_colors = {"CRITICO": "red", "ALTO": "yellow", "MEDIO": "orange1",
                   "BAJO": "green", "MUY BAJO": "cyan", "INOCUO": "dim"}
    risk_emojis = {"CRITICO": "💀", "ALTO": "🔴", "MEDIO": "🟡", "BAJO": "🟢",
                   "MUY BAJO": "🟩", "INOCUO": "✅"}
    risk_color = risk_colors.get(attack['risk_level'], "white")
    risk_emoji = risk_emojis.get(attack['risk_level'], "❓")
    table.add_row("NIVEL DE RIESGO TÉCNICO",
                  Text(f"{risk_emoji} {attack['risk_level']}", style=f"bold {risk_color}"))
    table.add_row("🎯 Puntuación técnica", f"{attack['risk_score']}/100")
    console.print(table, markup=False)

    if narrative_data.get("total_markers", 0) > 0:
        disclaimer_text = Text()
        disclaimer_text.append("⚠ AVISO\n", style="bold yellow")
        disclaimer_text.append(narrative_data.get("disclaimer", NARRATIVE_DISCLAIMER),
                               style="dim")
        console.print(Panel(disclaimer_text, border_style="yellow",
                            title="🗣 ANÁLISIS NARRATIVO"))

    ws_table = Table(title=f"🔒 AUDITORÍA DE SEGURIDAD WEB — {target.upper()}",
                     box=box.DOUBLE_EDGE, title_style="bold cyan")
    ws_table.add_column("📌 Chequeo", style="bold yellow", width=25)
    ws_table.add_column("📋 Resultado", style="white", width=55)

    ssl_info = web_security.get('ssl', {})
    if ssl_info.get('ok'):
        ws_table.add_row("🔐 SSL/TLS",
                         f"{ssl_info.get('version', 'N/A')} | "
                         f"Cifrado: {ssl_info.get('cipher', 'N/A')} | "
                         f"Emisor: {ssl_info.get('issuer', 'N/A')}")
        if ssl_info.get('days_left') is not None:
            ws_table.add_row("📆 Caducidad certificado",
                             f"{ssl_info.get('expires', 'N/A')} "
                             f"({ssl_info['days_left']} días restantes)")
    else:
        ws_table.add_row("🔐 SSL/TLS", f"⚠ No disponible ({ssl_info.get('error', 'N/A')})")

    if not web_security.get('reachable', False):
        ws_table.add_row("⚠ Contenido HTTP",
                         web_security.get('error', 'Sitio no accesible por HTTP(S)'))
    else:
        http_info = web_security.get('http', {})
        ws_table.add_row("🌐 HTTP",
                         f"Estado: {http_info.get('status_code', 'N/A')} | "
                         f"Tiempo: {http_info.get('time', 0):.2f}s | "
                         f"Tamaño: {http_info.get('size', 0):,} bytes | "
                         f"Redirecciones: {http_info.get('redirects', 0)}")
        if http_info.get('final_url'):
            ws_table.add_row("🌐 URL final", http_info['final_url'][:80])
        if http_info.get('downgraded'):
            ws_table.add_row("⚠ Sin TLS", "HTTPS falló y se descargó por HTTP plano")
        if http_info.get('truncated'):
            ws_table.add_row("✂ Descarga truncada",
                             f"Analizados primeros {MAX_BODY_BYTES:,} bytes")

    sec_headers = web_security.get('security_headers', {})
    headers_ok = sum(1 for v in sec_headers.values() if v != 'No configurado')
    ws_table.add_row("🔒 Cabeceras de seguridad",
                     f"{headers_ok}/{len(sec_headers)} configuradas")

    cookies = web_security.get('cookies', [])
    ws_table.add_row("🍪 Cookies", f"{len(cookies)} encontradas" if cookies else "Ninguna")

    suspicious = web_security.get('suspicious_patterns', [])
    if suspicious:
        tipos = ", ".join(sorted(set(m['type'] for m in suspicious)))
        ws_table.add_row("🔎 Patrones sospechosos",
                         f"⚠ {len(suspicious)}: {tipos}"[:250])
    else:
        ws_table.add_row("🔎 Patrones sospechosos", "0 (ninguno relevante)")

    techs = web_security.get('technologies', [])
    ws_table.add_row("🛠 Tecnologías", ", ".join(techs) if techs else "No detectadas")

    vt = web_security.get('virustotal', {})
    if vt.get('enabled'):
        if vt.get('ok') and vt.get('not_found'):
            ws_table.add_row("🔬 VirusTotal", "Dominio no encontrado en VT")
        elif vt.get('ok'):
            ws_table.add_row("🔬 VirusTotal",
                             f"🔴 Maliciosas: {vt.get('malicious', 0)} | "
                             f"🟡 Sospechosas: {vt.get('suspicious', 0)} | "
                             f"🟢 Limpias: {vt.get('harmless', 0)} | "
                             f"Reputación: {vt.get('reputation', 0)}")
            if vt.get('flagged_by'):
                ws_table.add_row("   ↳ Motores que lo marcan", ", ".join(vt['flagged_by']))
        else:
            ws_table.add_row("🔬 VirusTotal", f"⚠ {vt.get('error', 'N/A')}")
    else:
        ws_table.add_row("🔬 VirusTotal",
                         f"Deshabilitado: {vt.get('error', 'falta VT_API_KEY')}")

    gsb = web_security.get('safe_browsing', {})
    if gsb.get('enabled'):
        if gsb.get('ok'):
            ws_table.add_row("🛡 Safe Browsing",
                             "🔴 DETECTADO: " + ", ".join(gsb.get('matches') or [])
                             if gsb.get('detected') else "✅ Limpio")
        else:
            ws_table.add_row("🛡 Safe Browsing", f"⚠ {gsb.get('error', 'N/A')}")
    else:
        ws_table.add_row("🛡 Safe Browsing", "Deshabilitado (falta GSB_API_KEY)")

    uh = web_security.get('urlhaus', {})
    if uh.get('ok'):
        ws_table.add_row("🎣 URLHaus",
                         f"🔴 LISTADO ({uh.get('threat')}) | Ref: {uh.get('reference', 'N/A')}"
                         if uh.get('detected') else "✅ No listado")
    else:
        ws_table.add_row("🎣 URLHaus", f"⚠ {uh.get('error', 'N/A')}")

    ws_risk_colors = {"CRÍTICO": "red", "ALTO": "yellow", "MEDIO": "orange1", "BAJO": "green"}
    ws_level = web_security.get('risk_level', 'N/A')
    ws_color = ws_risk_colors.get(ws_level, "white")
    ws_table.add_row("🎯 RIESGO WEB SECURITY",
                     Text(f"{ws_level} ({web_security.get('risk_score', 0)}/100)",
                          style=f"bold {ws_color}"))
    console.print(ws_table, markup=False)

    cookies_detail = web_security.get('cookies', [])
    if cookies_detail:
        cookie_table = Table(title=f"🍪 COOKIES ({len(cookies_detail)})",
                             box=box.SIMPLE, title_style="bold yellow")
        cookie_table.add_column("Nombre", style="white", width=25)
        cookie_table.add_column("HttpOnly", width=10)
        cookie_table.add_column("Secure", width=10)
        cookie_table.add_column("SameSite", width=15)
        for c in cookies_detail:
            cookie_table.add_row(c['name'],
                                 Text("✅" if c['httpOnly'] else "❌",
                                      style="green" if c['httpOnly'] else "red"),
                                 Text("✅" if c['secure'] else "❌",
                                      style="green" if c['secure'] else "red"),
                                 Text(c['sameSite'],
                                      style="red" if c['sameSite'] == 'No configurado' else "green"))
        console.print(cookie_table, markup=False)

    vulns = web_security.get('vulnerabilities', [])
    if vulns:
        sev_order = {"Alta": 0, "Media": 1, "Baja": 2}
        sev_colors = {"Alta": "red", "Media": "yellow", "Baja": "cyan"}
        vulns_sorted = sorted(vulns, key=lambda v: sev_order.get(v['severity'], 3))
        vuln_table = Table(title=f"⚠ VULNERABILIDADES ({len(vulns_sorted)})",
                           box=box.SIMPLE, title_style="bold red")
        vuln_table.add_column("Sev.", width=7)
        vuln_table.add_column("Hallazgo", style="white", width=30)
        vuln_table.add_column("Detalle", style="dim", width=30)
        vuln_table.add_column("Recomendación", style="green", width=35)
        for v in vulns_sorted[:40]:
            color = sev_colors.get(v['severity'], 'white')
            vuln_table.add_row(Text(v['severity'], style=f"bold {color}"),
                               v['title'], v['detail'], v['recommendation'])
        console.print(vuln_table, markup=False)

    mitre = web_security.get('mitre_attack', [])
    if mitre:
        mitre_table = Table(title="🎯 MITRE ATT&CK — TÉCNICAS CORRELACIONADAS",
                            box=box.SIMPLE, title_style="bold red")
        mitre_table.add_column("Técnica", style="bold cyan", width=12)
        mitre_table.add_column("Nombre", style="white", width=35)
        mitre_table.add_column("Táctica", style="magenta", width=22)
        mitre_table.add_column("Evidencia", style="dim", width=45)
        for t in mitre:
            mitre_table.add_row(t['id'], t['name'], t['tactic'], t['evidence'])
        console.print(mitre_table, markup=False)
    else:
        console.print(Panel("✅ Sin técnicas MITRE correlacionadas.",
                            border_style="green", title="🎯 MITRE ATT&CK"),
                      markup=False)

    iocs = web_security.get('iocs', {})
    total_iocs = len(iocs.get('ips', [])) + len(iocs.get('domains', [])) + \
                  len(iocs.get('urls', [])) + len(iocs.get('hashes', []))
    if total_iocs:
        ioc_table = Table(title=f"📌 IOCs DETECTADOS ({total_iocs})",
                          box=box.SIMPLE, title_style="bold yellow")
        ioc_table.add_column("Tipo", style="bold cyan", width=10)
        ioc_table.add_column("Valor", style="white", width=90)
        for ip in iocs.get('ips', []):
            ioc_table.add_row("IP", ip)
        for d in iocs.get('domains', []):
            ioc_table.add_row("Dominio", d)
        for u in iocs.get('urls', []):
            ioc_table.add_row("URL", u)
        for h in iocs.get('hashes', []):
            ioc_table.add_row("Hash", h)
        console.print(ioc_table, markup=False)

    c2 = web_security.get('c2_assessment', {})
    c2_level = c2.get('level', 'SIN EVIDENCIA')
    c2_color = "red" if "PROBABLE" in c2_level else ("yellow" if "INDICIOS" in c2_level else "green")
    c2_text = Text()
    c2_text.append(f"📡 {c2_level} ({c2.get('score', 0)}/100)\n\n", style=f"bold {c2_color}")
    if c2.get('signals'):
        c2_text.append("Señales pasivas:\n")
        for s in c2['signals']:
            c2_text.append(f"  ✗ {s}\n")
    else:
        c2_text.append("Sin señales de C2 en las fuentes consultadas.\n")
    c2_text.append("\nℹ Basado en reputación externa: no confirma por sí solo infraestructura C2.",
                   style="dim")
    console.print(Panel(c2_text, border_style=c2_color, title="📡 EVALUACIÓN C2 (PASIVA)"))

    render_osint_table(target, osint)
    wait_for_enter()


async def scan_batch(scanner):
    console.print("\n📦 ESCANEO MASIVO", markup=False)
    console.print("📝 Ingresa lista de objetivos separados por comas", markup=False)
    input_str = Prompt.ask("📋 Lista")
    if not input_str:
        return
    targets = [t.strip() for t in input_str.split(',') if t.strip()]
    if not targets:
        return
    if len(targets) > MAX_BATCH_TARGETS:
        console.print(f"⚠ Máximo {MAX_BATCH_TARGETS} objetivos: se recortan.",
                      markup=False)
        targets = targets[:MAX_BATCH_TARGETS]
    console.print(f"\n🔍 Escaneando {len(targets)} objetivos...", markup=False)

    results = []
    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TimeRemainingColumn(), console=console) as p:
        task = p.add_task("🔄 Escaneando batch...", total=len(targets))
        for target in targets:
            p.update(task, description=f"🔍 {escape(target)}...")
            try:
                result = await scanner.full_scan(target, include_osint=False)
                results.append(result)
            except Exception as e:
                results.append({"target": target, "error": _safe_err(e, 100)})
            p.update(task, advance=1)
            await asyncio.sleep(1)

    table = Table(title="📊 RESUMEN DEL ESCANEO MASIVO",
                  box=box.ROUNDED, title_style="bold cyan")
    table.add_column("🎯 Objetivo", style="cyan", width=25)
    table.add_column("📊 Riesgo", style="bold", width=12)
    table.add_column("🎯 Score", style="yellow", width=8)
    table.add_column("🗣 Marcadores", style="dim", width=12)
    table.add_column("🔒 Web Sec", style="dim", width=10)
    for r in results:
        if "error" in r:
            table.add_row(r['target'], "❌ ERROR", "N/A", "N/A", "N/A")
        else:
            color = "red" if r.get('risk_level') == "CRITICO" else \
                    "yellow" if r.get('risk_level') in ["ALTO", "MEDIO"] else "green"
            table.add_row(r.get('target', 'N/A'),
                          Text(r.get('risk_level', 'N/A'), style=color),
                          f"{r.get('risk_score', 0)}",
                          f"{r.get('narrative', {}).get('total_markers', 0)}",
                          r.get('web_security', {}).get('risk_level', 'N/A'))
    console.print(table, markup=False)

    risk_counts = Counter(r.get('risk_level', 'N/A') for r in results if 'error' not in r)
    console.print("\n📈 ESTADÍSTICAS DEL BATCH:", markup=False)
    for lvl in ("CRITICO", "ALTO", "MEDIO", "BAJO", "MUY BAJO", "INOCUO"):
        console.print(f"  • {lvl}: {risk_counts.get(lvl, 0)}", markup=False)
    wait_for_enter()


def show_stats():
    console.print("\n📈 ESTADÍSTICAS DETALLADAS", markup=False)
    stats = logger.get_stats()
    threats = logger.get_threats()
    table = Table(title="📊 MÉTRICAS DEL SISTEMA",
                  box=box.DOUBLE_EDGE, title_style="bold cyan")
    table.add_column("📌 Métrica", style="bold yellow", width=25)
    table.add_column("📋 Valor", style="white", width=25)
    table.add_row("📊 Total eventos", str(stats['total_events']))
    table.add_row("💀 Eventos críticos", str(stats['critical']))
    table.add_row("⚠ Alertas", str(stats['warning']))
    table.add_row("ℹ Eventos normales", str(stats['info']))
    table.add_row("🎯 Amenazas totales", str(stats['total_threats']))
    table.add_row("🎯 Objetivos únicos", str(stats.get('unique_targets', 0)))
    table.add_row("📈 Tasa de amenazas", f"{stats.get('threat_rate', 0):.1%}")
    table.add_row("⭐ Reputación promedio", f"{stats.get('avg_reputation', 0):>+.1f}")
    console.print(table, markup=False)
    if threats:
        console.print("\n🚨 ÚLTIMAS AMENAZAS:", markup=False)
        threat_table = Table(box=box.ROUNDED)
        threat_table.add_column("🕐 Fecha", style="dim", width=20)
        threat_table.add_column("🎯 Origen", style="cyan", width=25)
        threat_table.add_column("📝 Mensaje", style="white", width=40)
        for t in threats[-5:]:
            threat_table.add_row(t.get('timestamp', 'N/A')[:19], t.get('origin', 'N/A')[:23],
                                t.get('message', 'N/A')[:38])
        console.print(threat_table, markup=False)
    wait_for_enter()


def start_dashboard():
    console.print("\n📈 INICIANDO DASHBOARD WEB", markup=False)
    try:
        from flask import Flask, render_template_string, jsonify, request, abort
        app = Flask(__name__)
        HTML = """
<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta http-equiv="refresh" content="30">
<title>CircinusWatch v8.1 - Dashboard</title><style>
body { background:#0a0a0a; color:#00ff41; font-family:'Courier New', monospace; padding:20px; }
h1 { color:#ff0000; text-align:center; border-bottom:2px solid #ff0000; padding-bottom:10px; }
.metrics { display:grid; grid-template-columns:repeat(auto-fit, minmax(150px,1fr)); gap:15px; margin:20px 0; }
.metric { background:#111; border:1px solid #333; padding:15px; border-radius:10px; text-align:center; }
.value { font-size:28px; font-weight:bold; }
.critical { color:#ff0000; } .warning { color:#ffaa00; } .success { color:#00ff41; } .info { color:#00ccff; }
table { width:100%; border-collapse:collapse; margin-top:20px; }
th, td { padding:8px; border-bottom:1px solid #222; text-align:left; } th { color:#ff4444; }
</style></head><body>
<h1>🌀 CIRCINUSWATCH v8.1</h1>
<p style="text-align:center;">{{ now }} | 🟢 Sistema Activo | ⚖️ 100% Pasivo</p>
<div class="metrics">
<div class="metric"><div>💀 Críticas</div><div class="value critical">{{ stats.critical }}</div></div>
<div class="metric"><div>⚠ Alertas</div><div class="value warning">{{ stats.warning }}</div></div>
<div class="metric"><div>ℹ Eventos</div><div class="value info">{{ stats.total_events }}</div></div>
<div class="metric"><div>⭐ Reputación</div><div class="value">{{ "%.1f"|format(stats.avg_reputation) }}</div></div>
</div>
<h3>🆕 Últimos Eventos</h3>
<table><tr><th>🕐 Hora</th><th>🎯 Origen</th><th>📊 Nivel</th><th>📝 Mensaje</th></tr>
{% for log in logs %}<tr><td>{{ log.timestamp[:16] }}</td><td>{{ log.origin[:15] }}</td>
<td>{{ log.level }}</td><td>{{ log.message[:35] }}</td></tr>{% endfor %}</table>
<p style="text-align:center;margin-top:20px;color:#444;">🔄 Actualiza cada 30s</p>
</body></html>
"""
        @app.before_request
        def _only_local_host():
            host = (request.host or "").split(':')[0].lower()
            if host not in ("127.0.0.1", "localhost"):
                abort(403)

        @app.after_request
        def _security_headers(resp):
            resp.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
            resp.headers['X-Content-Type-Options'] = 'nosniff'
            resp.headers['X-Frame-Options'] = 'DENY'
            resp.headers['Referrer-Policy'] = 'no-referrer'
            resp.headers['Cache-Control'] = 'no-store'
            return resp

        @app.route('/')
        def dashboard():
            return render_template_string(HTML, now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                           stats=logger.get_stats(), logs=logger.get_last_events(15))

        @app.route('/api/stats')
        def api_stats():
            return jsonify(logger.get_stats())

        console.print("📈 Dashboard iniciado en http://localhost:5000 (Ctrl+C para volver)",
                      markup=False)
        import webbrowser
        webbrowser.open("http://localhost:5000")
        app.run(host='127.0.0.1', port=5000, debug=False)
    except Exception as e:
        console.print(f"❌ Error iniciando dashboard: {_safe_err(e, 200)}", markup=False)
    wait_for_enter()


def show_logs():
    console.print("\n📜 HISTORIAL DE OPERACIONES", markup=False)
    logs = logger.get_all_events()
    if not logs:
        console.print("📭 No hay logs registrados", markup=False)
        wait_for_enter()
        return
    table = Table(title="📋 Últimos 30 eventos", box=box.ROUNDED, title_style="bold cyan")
    table.add_column("🕐 Timestamp", style="dim", width=22)
    table.add_column("🎯 Origen", style="cyan", width=25)
    table.add_column("📊 Nivel", width=12)
    table.add_column("📝 Mensaje", width=50)
    for log in logs[-30:]:
        level = log.get("level", "INFO")
        if level == "CRITICAL":
            color, emoji = "red", "💀"
        elif level == "WARNING":
            color, emoji = "yellow", "⚠"
        else:
            color, emoji = "green", "ℹ"
        table.add_row(log.get("timestamp", "N/A")[:19], log.get("origin", "N/A")[:24],
                     Text(f"{emoji} {level}", style=color), log.get("message", "")[:48])
    console.print(table, markup=False)
    wait_for_enter()


def manage_lists(scanner):
    console.print("\n⛔ GESTIÓN DE LISTAS", markup=False)
    while True:
        console.print("\n📋 GESTIÓN DE REPUTACIÓN", markup=False)
        console.print("  1. 📋 Ver lista negra", markup=False)
        console.print("  2. 📋 Ver lista blanca", markup=False)
        console.print("  3. ➕ Agregar a lista negra", markup=False)
        console.print("  4. ➕ Agregar a lista blanca", markup=False)
        console.print("  5. ❌ Eliminar de lista negra", markup=False)
        console.print("  6. ❌ Eliminar de lista blanca", markup=False)
        console.print("  7. 🔙 Volver", markup=False)
        choice = Prompt.ask("📌 Opción", choices=["1", "2", "3", "4", "5", "6", "7"])
        if choice == "7":
            break
        elif choice == "1":
            blacklist = scanner.reputation_analyzer.blacklist
            if blacklist:
                console.print("\n⛔ LISTA NEGRA:", markup=False)
                for target, info in blacklist.items():
                    console.print(f"  • {target} - {info.get('reason', 'Sin razón')}",
                                  markup=False)
            else:
                console.print("✅ No hay objetivos en lista negra", markup=False)
            wait_for_enter()
        elif choice == "2":
            whitelist = scanner.reputation_analyzer.whitelist
            if whitelist:
                console.print("\n✅ LISTA BLANCA:", markup=False)
                for target, info in whitelist.items():
                    console.print(f"  • {target} - {info.get('reason', 'Sin razón')}",
                                  markup=False)
            else:
                console.print("✅ No hay objetivos en lista blanca", markup=False)
            wait_for_enter()
        elif choice in ("3", "4"):
            target = Prompt.ask("🎯 Ingresa el objetivo").strip()
            if target:
                reason = Prompt.ask("📝 Razón (opcional)", default="Manual")
                if choice == "3":
                    scanner.reputation_analyzer.add_to_blacklist(target, reason)
                    console.print(f"✅ {target} agregado a lista negra", markup=False)
                else:
                    scanner.reputation_analyzer.add_to_whitelist(target, reason)
                    console.print(f"✅ {target} agregado a lista blanca", markup=False)
                wait_for_enter()
        elif choice == "5":
            blacklist = scanner.reputation_analyzer.blacklist
            if not blacklist:
                console.print("✅ No hay objetivos en lista negra", markup=False)
                wait_for_enter()
                continue
            for i, (target, info) in enumerate(blacklist.items(), 1):
                console.print(f"  {i}. {target} - {info.get('reason', 'Sin razón')}", markup=False)
            sel = Prompt.ask("🔢 Número a eliminar (0 para cancelar)")
            try:
                idx = int(sel) - 1
                if 0 <= idx < len(blacklist):
                    target = list(blacklist.keys())[idx]
                    scanner.reputation_analyzer.remove_from_blacklist(target)
                    console.print(f"✅ {target} eliminado de lista negra", markup=False)
            except Exception:
                console.print("❌ Entrada inválida", markup=False)
            wait_for_enter()
        elif choice == "6":
            whitelist = scanner.reputation_analyzer.whitelist
            if not whitelist:
                console.print("✅ No hay objetivos en lista blanca", markup=False)
                wait_for_enter()
                continue
            for i, (target, info) in enumerate(whitelist.items(), 1):
                console.print(f"  {i}. {target} - {info.get('reason', 'Sin razón')}", markup=False)
            sel = Prompt.ask("🔢 Número a eliminar (0 para cancelar)")
            try:
                idx = int(sel) - 1
                if 0 <= idx < len(whitelist):
                    target = list(whitelist.keys())[idx]
                    scanner.reputation_analyzer.remove_from_whitelist(target)
                    console.print(f"✅ {target} eliminado de lista blanca", markup=False)
            except Exception:
                console.print("❌ Entrada inválida", markup=False)
            wait_for_enter()


def backup_data():
    console.print("\n💾 CREANDO BACKUP", markup=False)
    try:
        backup_file = logger.backup_logs()
        console.print(f"✅ Backup creado: {backup_file}", markup=False)
        list_backup = f"backups/lists_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        _write_json(list_backup, {"blacklist": ReputationAnalyzer()._load(BLACKLIST_FILE),
                                  "whitelist": ReputationAnalyzer()._load(WHITELIST_FILE),
                                  "timestamp": datetime.now().isoformat()})
        console.print(f"✅ Backup de listas creado: {list_backup}", markup=False)
    except Exception as e:
        console.print(f"❌ Error creando backup: {_safe_err(e, 200)}", markup=False)
    wait_for_enter()


def export_report():
    console.print("\n📤 EXPORTANDO REPORTE", markup=False)
    try:
        stats = logger.get_stats()
        threats = logger.get_threats()
        logs = logger.get_all_events()
        rep = logger.get_reputation()
        report = {"generated": datetime.now().isoformat(), "version": APP_VERSION,
                  "tool": APP_NAME, "stats": stats, "threats_count": len(threats),
                  "total_events": len(logs), "reputation": rep,
                  "summary": {"critical_count": stats['critical'],
                              "warning_count": stats['warning'],
                              "info_count": stats['info'],
                              "unique_targets": stats.get('unique_targets', 0),
                              "threat_rate": stats.get('threat_rate', 0),
                              "avg_reputation": stats.get('avg_reputation', 0)},
                  "recent_events": logs[-20:] if logs else []}
        filename = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        _write_json(filename, report)
        console.print(f"✅ Reporte exportado: {filename}", markup=False)
        console.print(f"📊 Tamaño: {os.path.getsize(filename)} bytes", markup=False)
    except Exception as e:
        console.print(f"❌ Error exportando reporte: {_safe_err(e, 200)}", markup=False)
    wait_for_enter()


def clear_logs():
    if Confirm.ask("⚠ ¿Seguro que quieres eliminar TODOS los logs?", default=False):
        if Confirm.ask("🔄 ¿Hacer backup antes de limpiar?"):
            backup_data()
        logger.clear_logs()
        console.print("🗑 Logs limpiados exitosamente", markup=False)
        time.sleep(1)


_STIX_NS = uuid.UUID("6f1f2a1e-5a0b-4c5e-9d57-3c1c0a7b1e42")


def _stix_escape(value):
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def export_stix_bundle(result):
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + "Z"
    target = result.get("target", "unknown")
    ip = result.get("geolocation", {}).get("ip") or \
         result.get("osint", {}).get("shodan_passive", {}).get("ip")
    pattern_parts = []
    if ip and ip != "N/A" and _is_ip(ip):
        if ':' in ip:
            pattern_parts.append(f"[ipv6-addr:value = '{_stix_escape(ip)}']")
        else:
            pattern_parts.append(f"[ipv4-addr:value = '{_stix_escape(ip)}']")
    host = _extract_host(target) or target
    if not _is_ip(host):
        pattern_parts.append(f"[domain-name:value = '{_stix_escape(host)}']")
    if not pattern_parts:
        pattern_parts.append(f"[domain-name:value = '{_stix_escape(host)}']")
    ws = result.get("web_security", {})
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [{
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid5(_STIX_NS, target)}",
            "created": now, "modified": now,
            "name": f"{APP_NAME} scan: {target}",
            "pattern": " OR ".join(pattern_parts),
            "pattern_type": "stix", "valid_from": now,
            "labels": [result.get("risk_level", "unknown").lower()],
            "confidence": max(0, min(int(result.get("risk_score", 0)), 100)),
            "description": (
                f"Marcadores narrativos: {result.get('narrative', {}).get('total_markers', 0)} | "
                f"Riesgo web security: {ws.get('risk_level', 'N/A')} | "
                f"Subdominios (crt.sh): "
                f"{result.get('osint', {}).get('certificate_transparency', {}).get('total_subdomains', 'N/A')}"
            )
        }]
    }


async def export_stix(scanner):
    console.print("\n📤 EXPORTAR STIX", markup=False)
    history = _read_json(SCAN_HISTORY, [])
    if not isinstance(history, list):
        history = []
    if not history:
        console.print("⚠ No hay escaneos guardados todavía.", markup=False)
        wait_for_enter()
        return
    target = Prompt.ask("🌐 Objetivo a exportar (Enter = último escaneo)", default="")
    candidates = [h for h in history if not target or h['target'] == target]
    if not candidates:
        console.print(f"⚠ No hay escaneos guardados para '{target}'.", markup=False)
        wait_for_enter()
        return
    entry = candidates[-1]
    bundle = export_stix_bundle(entry['results'])
    filename = (f"reports/stix_{re.sub(r'[^a-zA-Z0-9]', '_', entry['target'])}_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    _write_json(filename, bundle)
    console.print(f"✅ Bundle STIX exportado: {filename}", markup=False)
    console.print(json.dumps(bundle, indent=2, ensure_ascii=False)[:1500], markup=False)
    wait_for_enter()


async def osint_extra_menu(scanner):
    console.print("\n🕵 OSINT EXTRA", markup=False)
    target = Prompt.ask("🌐 Objetivo").strip()
    if not target:
        return
    ok, why = validate_target(target)
    if not ok:
        console.print(f"❌ Objetivo inválido: {why}", markup=False)
        wait_for_enter()
        return
    with console.status(f"🕵 Consultando fuentes OSINT para {escape(target)}...",
                        spinner="dots"):
        osint = await scanner.osint_scan(target)
    render_osint_table(target, osint)
    wait_for_enter()


async def watchlist_menu(scanner):
    wl = scanner.watchlist_analyzer
    while True:
        console.print("\n👁 VIGILANCIA PERIÓDICA", markup=False)
        wl_table = Table(box=box.ROUNDED, border_style="magenta")
        wl_table.add_column("Objetivo", style="bold white")
        wl_table.add_column("Último riesgo", style="white")
        wl_table.add_column("Web security", style="white")
        wl_table.add_column("Última revisión", style="dim")
        if not wl.watchlist:
            console.print("📭 La watchlist está vacía.", markup=False)
        else:
            for t, entry in wl.watchlist.items():
                wl_table.add_row(t, entry.get('last_risk_level') or "Sin revisar",
                                 entry.get('last_web_security_level') or "N/A",
                                 entry.get('last_checked') or "Nunca")
            console.print(wl_table, markup=False)
        console.print("\n1) Agregar   2) Quitar   3) Correr ciclo   0) Volver", markup=False)
        opt = Prompt.ask("📌 Opción", choices=["1", "2", "3", "0"], default="0")
        if opt == "0":
            break
        elif opt == "1":
            t = Prompt.ask("🌐 Objetivo a agregar").strip()
            if t:
                ok, why = validate_target(t)
                if not ok:
                    console.print(f"❌ Objetivo inválido: {why}", markup=False)
                    continue
                added = wl.add(t)
                console.print("✅ Agregado." if added else "⚠ Ya estaba en la watchlist.",
                              markup=False)
        elif opt == "2":
            t = Prompt.ask("🌐 Objetivo a quitar")
            if t:
                removed = wl.remove(t)
                console.print("✅ Quitado." if removed else "⚠ No estaba.",
                              markup=False)
        elif opt == "3":
            if not wl.watchlist:
                console.print("📭 No hay objetivos para revisar.", markup=False)
                continue
            for t in list(wl.watchlist.keys()):
                console.print(f"🔍 Revisando {t}...", markup=False)
                try:
                    result = await scanner.full_scan(t, include_osint=False)
                except Exception as e:
                    console.print(f"   ❌ Error en {t}: {_safe_err(e, 120)}", markup=False)
                    continue
                changed = wl.update(t, result['risk_score'], result['risk_level'],
                                    result.get('web_security', {}).get('risk_level', 'N/A'))
                if changed:
                    console.print(f"⚠ CAMBIO detectado en {t}: {result['risk_level']}",
                                  markup=False)
                    await scanner.send_telegram_alert(
                        f"👁 {APP_NAME} — cambio en vigilancia\nObjetivo: {t}\n"
                        f"Nuevo riesgo: {result['risk_level']} ({result['risk_score']}/100)")
                else:
                    console.print(f"   sin cambios ({result['risk_level']})", markup=False)
                await asyncio.sleep(2)
            wait_for_enter()


async def main():
    scanner = CircinusScanner(
        vt_api_key=VT_API_KEY,
        abuseipdb_key=ABUSEIPDB_API_KEY,
        greynoise_key=GREYNOISE_API_KEY,
        shodan_key=SHODAN_API_KEY,
        gsb_key=GSB_API_KEY,
        urlhaus_auth_key=URLHAUS_AUTH_KEY,
        telegram_token=TELEGRAM_BOT_TOKEN,
        telegram_chat_id=TELEGRAM_CHAT_ID
    )

    console.print(Panel(
        f"🌀 CIRCINUSWATCH v{APP_VERSION}\n"
        f"⚡ Modo: {scanner.mode}\n\n"
        f"🔬 VirusTotal: {_mask(scanner.vt_api_key)}\n"
        f"🛡 Safe Browsing: {_mask(scanner.gsb_key)}\n"
        f"🎣 URLHaus: {_mask(scanner.urlhaus_auth_key)}\n"
        f"🚫 AbuseIPDB: {_mask(scanner.abuseipdb_key)}\n"
        f"🌫 GreyNoise: {_mask(scanner.greynoise_key)}\n"
        f"🔭 Shodan: {_mask(scanner.shodan_key)}\n"
        f"📨 Telegram: {_mask(scanner.telegram_token)}\n",
        border_style="red", title="🔥 SISTEMA INICIADO"), markup=False)

    time.sleep(1)

    while True:
        show_banner(scanner)
        show_menu()
        choice = Prompt.ask("📌 Selecciona una opción",
                           choices=["1", "2", "3", "4", "5", "6", "7", "8",
                                    "9", "10", "11", "12", "0"])

        if choice == "1":
            await scan_target(scanner)
        elif choice == "2":
            start_dashboard()
        elif choice == "3":
            show_logs()
        elif choice == "4":
            await scan_batch(scanner)
        elif choice == "5":
            show_stats()
        elif choice == "6":
            clear_logs()
        elif choice == "7":
            manage_lists(scanner)
        elif choice == "8":
            backup_data()
        elif choice == "9":
            export_report()
        elif choice == "10":
            await osint_extra_menu(scanner)
        elif choice == "11":
            await watchlist_menu(scanner)
        elif choice == "12":
            await export_stix(scanner)
        elif choice == "0":
            console.print(f"👋 Cerrando {APP_NAME}.", markup=False)
            break


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n👋 Interrumpido por el usuario. Hasta pronto.", markup=False)        
