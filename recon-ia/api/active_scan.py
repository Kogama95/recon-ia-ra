"""
active_scan.py
==============
Module de reconnaissance active gouvernée par agents IA.
Placé dans api/ aux côtés de main.py existant.

Auteur    : Gaston Mahugnon KOHOUNKO
Directeur : Dr. Emery ASSOGBA
Université : IFRI — Université d'Abomey-Calavi — 2024-2025

Ce module s'ajoute à la plateforme passive recon-ia sans modifier
le code existant. Il expose 3 nouvelles routes Flask appelées
depuis le frontend ou depuis les workflows n8n.
"""

import nmap
import subprocess
import json
import sqlite3
import hashlib
import os
import re
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional, Tuple, List

# ──────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────

DB_PATH    = os.getenv("AUDIT_DB_PATH", "/app/data/audit.sqlite")
SCOPE_FILE = os.getenv("SCOPE_FILE",    "/app/config/scope.json")
MAX_RATE   = int(os.getenv("MASSCAN_MAX_RATE", "50"))

# ──────────────────────────────────────────────
# MODÈLES DE DONNÉES
# ──────────────────────────────────────────────

@dataclass
class ScanResult:
    target:    str
    agent:     str
    timestamp: str
    data:      dict
    integrity: str = ""

    def __post_init__(self):
        raw = f"{self.target}{self.agent}{self.timestamp}{json.dumps(self.data, sort_keys=True)}"
        self.integrity = hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class ActiveScanReport:
    target:           str
    timestamp_start:  str
    timestamp_end:    str
    authorized:       bool
    passive_context:  dict
    masscan:          dict
    nmap:             dict
    analysis:         dict
    audit_trail:      list
    error:            Optional[str] = None


# ──────────────────────────────────────────────
# COUCHE 2 — GOUVERNANCE & TRAÇABILITÉ
# ──────────────────────────────────────────────

class GovernanceModule:
    """
    Aucun agent ne peut agir sans validation de ce module.
    Chaque action est journalisée avec horodatage et hash SHA-256.
    """

    def __init__(self):
        self.scope = self._load_scope()
        self._init_db()

    def _load_scope(self) -> dict:
        if os.path.exists(SCOPE_FILE):
            with open(SCOPE_FILE) as f:
                return json.load(f)
        return {
            "lab_mode": True,
            "authorized_networks": ["172.21.0.0/24"],
            "authorized_domains":  [],
            "allowed_ports":       "21,22,80,443,3306,8080",
            "max_scan_rate":       MAX_RATE
        }

    def _init_db(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                agent     TEXT NOT NULL,
                target    TEXT NOT NULL,
                action    TEXT NOT NULL,
                status    TEXT NOT NULL,
                details   TEXT,
                hash      TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def is_authorized(self, target: str) -> Tuple[bool, str]:
        if self.scope.get("lab_mode"):
            prefixes = ("172.21.", "172.20.", "127.", "localhost", "10.", "192.168.")
            if any(target.startswith(p) for p in prefixes):
                return True, "Cible dans le réseau de laboratoire autorisé"
        if target in self.scope.get("authorized_domains", []):
            return True, "Domaine explicitement autorisé"
        return False, f"Cible '{target}' hors périmètre. Ajoutez-la dans config/scope.json"

    def log(self, agent: str, target: str, action: str, status: str, details: dict = None) -> dict:
        ts      = datetime.now(timezone.utc).isoformat()
        details = json.dumps(details or {})
        h       = hashlib.sha256(f"{ts}{agent}{target}{action}{status}{details}".encode()).hexdigest()
        conn    = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO audit_log (timestamp,agent,target,action,status,details,hash) VALUES (?,?,?,?,?,?,?)",
            (ts, agent, target, action, status, details, h)
        )
        conn.commit()
        conn.close()
        return {"timestamp": ts, "agent": agent, "action": action, "status": status, "hash": h}

    def get_trail(self, target: str) -> List[dict]:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            "SELECT timestamp,agent,action,status,hash FROM audit_log WHERE target=? ORDER BY timestamp",
            (target,)
        ).fetchall()
        conn.close()
        return [{"timestamp": r[0], "agent": r[1], "action": r[2], "status": r[3], "hash": r[4]} for r in rows]


# ──────────────────────────────────────────────
# COUCHE 3 — AGENTS SPÉCIALISÉS
# ──────────────────────────────────────────────

class AgentMasscan:
    NAME = "AgentMasscan"

    def __init__(self, gov: GovernanceModule):
        self.gov      = gov
        self.max_rate = gov.scope.get("max_scan_rate", MAX_RATE)

    def run(self, target: str, ports: str = "1-1024") -> ScanResult:
        ts = datetime.now(timezone.utc).isoformat()
        self.gov.log(self.NAME, target, "SCAN_START", "INFO", {"ports": ports})
        try:
            proc = subprocess.run(
                ["masscan", target, f"-p{ports}", f"--rate={self.max_rate}",
                 "--output-format", "json", "--output-file", "-"],
                capture_output=True, text=True, timeout=60
            )
            open_ports = []
            raw = proc.stdout.strip().rstrip(",")
            if raw:
                if not raw.startswith("["):
                    raw = f"[{raw}]"
                try:
                    for entry in json.loads(raw):
                        for p in entry.get("ports", []):
                            open_ports.append({"port": p.get("port"), "proto": p.get("proto", "tcp")})
                except json.JSONDecodeError:
                    for line in proc.stdout.splitlines():
                        m = re.search(r"port (\d+)/(\w+)", line)
                        if m:
                            open_ports.append({"port": int(m.group(1)), "proto": m.group(2)})
            self.gov.log(self.NAME, target, "SCAN_COMPLETE", "SUCCESS", {"found": len(open_ports)})
            return ScanResult(target, self.NAME, ts, {"open_ports": open_ports, "count": len(open_ports)})
        except FileNotFoundError:
            self.gov.log(self.NAME, target, "TOOL_MISSING", "WARNING")
            return ScanResult(target, self.NAME, ts, {"open_ports": [], "error": "masscan non installé"})
        except subprocess.TimeoutExpired:
            self.gov.log(self.NAME, target, "TIMEOUT", "ERROR")
            return ScanResult(target, self.NAME, ts, {"open_ports": [], "error": "timeout 60s"})
        except Exception as e:
            self.gov.log(self.NAME, target, "ERROR", "ERROR", {"msg": str(e)})
            return ScanResult(target, self.NAME, ts, {"open_ports": [], "error": str(e)})


class AgentNmap:
    NAME = "AgentNmap"

    def __init__(self, gov: GovernanceModule):
        self.gov = gov
        self.nm  = nmap.PortScanner()

    def run(self, target: str, ports: list = None) -> ScanResult:
        ts       = datetime.now(timezone.utc).isoformat()
        port_str = ",".join(str(p["port"]) for p in ports if "port" in p) if ports else \
                   self.gov.scope.get("allowed_ports", "22,80,443,21,3306,8080")
        self.gov.log(self.NAME, target, "SCAN_START", "INFO", {"ports": port_str})
        try:
            self.nm.scan(hosts=target, ports=port_str, arguments="-sV -T3 --open --host-timeout 60s")
            services = []
            if target in self.nm.all_hosts():
                for proto in self.nm[target].all_protocols():
                    for port in self.nm[target][proto]:
                        s = self.nm[target][proto][port]
                        services.append({
                            "port":     port,
                            "protocol": proto,
                            "state":    s.get("state", ""),
                            "service":  s.get("name", ""),
                            "product":  s.get("product", ""),
                            "version":  s.get("version", "")
                        })
            self.gov.log(self.NAME, target, "SCAN_COMPLETE", "SUCCESS", {"found": len(services)})
            return ScanResult(target, self.NAME, ts, {"services": services, "count": len(services)})
        except Exception as e:
            self.gov.log(self.NAME, target, "ERROR", "ERROR", {"msg": str(e)})
            return ScanResult(target, self.NAME, ts, {"services": [], "error": str(e)})


# ──────────────────────────────────────────────
# COUCHE 4 — ORCHESTRATEUR
# ──────────────────────────────────────────────

class Orchestrator:
    """
    Pipeline graduel :
    1. Vérification autorisation (gouvernance)
    2. AgentMasscan → ports ouverts (rapide)
    3. AgentNmap    → services/versions (ciblé)
    4. Analyse      → scoring de risque + recommandations
    """

    def __init__(self):
        self.gov     = GovernanceModule()
        self.masscan = AgentMasscan(self.gov)
        self.nmap    = AgentNmap(self.gov)

    def run(self, target: str, passive_context: dict = None) -> ActiveScanReport:
        ts_start        = datetime.now(timezone.utc).isoformat()
        passive_context = passive_context or {}

        # Étape 1 — autorisation
        ok, reason = self.gov.is_authorized(target)
        self.gov.log("Orchestrator", target, "AUTH_CHECK", "GRANTED" if ok else "DENIED", {"reason": reason})

        if not ok:
            return ActiveScanReport(
                target=target, timestamp_start=ts_start,
                timestamp_end=datetime.now(timezone.utc).isoformat(),
                authorized=False, passive_context=passive_context,
                masscan={}, nmap={}, analysis={},
                audit_trail=self.gov.get_trail(target), error=reason
            )

        # Étape 2 — Masscan
        r_masscan = self.masscan.run(target)

        # Étape 3 — Nmap ciblé sur les ports ouverts trouvés
        r_nmap = self.nmap.run(target, r_masscan.data.get("open_ports", []))

        # Étape 4 — Analyse
        analysis = self._analyse(passive_context, r_masscan, r_nmap)

        self.gov.log("Orchestrator", target, "PIPELINE_DONE", "SUCCESS",
                     {"risk_score": analysis["risk_score"]})

        return ActiveScanReport(
            target=target, timestamp_start=ts_start,
            timestamp_end=datetime.now(timezone.utc).isoformat(),
            authorized=True, passive_context=passive_context,
            masscan=asdict(r_masscan), nmap=asdict(r_nmap),
            analysis=analysis, audit_trail=self.gov.get_trail(target)
        )

    def _analyse(self, passive_ctx: dict, r_masscan: ScanResult, r_nmap: ScanResult) -> dict:
        open_ports = r_masscan.data.get("open_ports", [])
        services   = r_nmap.data.get("services", [])
        score, findings, recommendations = 0, [], []

        # Ports sensibles
        risky = {
            21:   ("FTP",        20, "Remplacer FTP par SFTP"),
            22:   ("SSH",        10, "Vérifier config SSH (clés, fail2ban)"),
            23:   ("Telnet",     30, "Désactiver Telnet immédiatement"),
            80:   ("HTTP",        5, "Forcer HTTPS"),
            3306: ("MySQL",      25, "Ne pas exposer MySQL publiquement"),
            5432: ("PostgreSQL", 25, "Ne pas exposer PostgreSQL publiquement"),
            6379: ("Redis",      30, "Redis sans auth = risque critique"),
            27017:("MongoDB",    30, "MongoDB sans auth = risque critique"),
        }
        for p in open_ports:
            port = p.get("port")
            if port in risky:
                name, risk, reco = risky[port]
                score += risk
                findings.append(f"Port {port} ({name}) ouvert")
                if reco:
                    recommendations.append(reco)

        # Versions obsolètes
        obsolete = ["apache/2.2", "apache/2.0", "openssl/1.0", "php/5.", "php/7.0", "php/7.1"]
        for s in services:
            vs = f"{s.get('product','').lower()}/{s.get('version','').lower()}"
            for kw in obsolete:
                if kw in vs:
                    score += 15
                    findings.append(f"Version obsolète : {s['product']} {s['version']}")
                    recommendations.append(f"Mettre à jour {s['product']}")

        # Delta passif / actif
        passive_ports = set(passive_ctx.get("open_ports", []))
        active_ports  = {p["port"] for p in open_ports}
        new_ports     = active_ports - passive_ports
        if new_ports:
            score += len(new_ports) * 5
            findings.append(f"Ports non vus passivement mais actifs : {sorted(new_ports)}")
            recommendations.append("Investiguer les ports découverts uniquement en actif")

        score = min(score, 100)
        level = "CRITIQUE" if score >= 70 else "ÉLEVÉ" if score >= 40 else "MODÉRÉ" if score >= 20 else "FAIBLE"

        return {
            "risk_score":            score,
            "risk_level":            level,
            "findings":              findings,
            "recommendations":       list(set(recommendations)),
            "open_ports_count":      len(open_ports),
            "services_count":        len(services),
            "false_positives_avoided": len(passive_ports - active_ports),
            "passive_active_delta": {
                "passive_only":  sorted(passive_ports - active_ports),
                "active_only":   sorted(new_ports),
                "confirmed":     sorted(passive_ports & active_ports)
            }
        }
