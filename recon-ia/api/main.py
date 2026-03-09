from flask import Flask, jsonify, request
import whois
from datetime import datetime

# ── Module reconnaissance active (KOHOUNKO — Master 2024-2025) ───
from active_scan import Orchestrator, GovernanceModule
from dataclasses import asdict

app = Flask(__name__)
orchestrator = Orchestrator()

# ════════════════════════════════════════════════════════════════
# ROUTES EXISTANTES — reconnaissance passive (inchangées)
# ════════════════════════════════════════════════════════════════

def custom_whois(domain):
    try:
        w = whois.whois(domain)
        creation_date   = w.creation_date
        expiration_date = w.expiration_date
        updated_date    = w.updated_date
        if isinstance(creation_date, list):   creation_date   = creation_date[0]
        if isinstance(expiration_date, list): expiration_date = expiration_date[0]
        if isinstance(updated_date, list):    updated_date    = updated_date[0]
        result = {
            "domain":                   domain,
            "creation_date":            creation_date.strftime("%Y-%m-%d")   if creation_date   else None,
            "expiration_date":          expiration_date.strftime("%Y-%m-%d") if expiration_date else None,
            "last_updated":             updated_date.strftime("%Y-%m-%d")    if updated_date    else None,
            "registrar":                w.registrar,
            "registrant_name":          w.name if hasattr(w, 'name') else None,
            "registrant_organization":  w.org  if hasattr(w, 'org')  else None,
            "registrant_country":       w.country if hasattr(w, 'country') else None,
            "name_servers":             list(set(w.name_servers)) if w.name_servers else [],
            "status":                   w.status if w.status else None,
            "emails":                   w.emails if hasattr(w, 'emails') else []
        }
        if result['emails']:
            result['emails'] = list(set(
                e.lower().strip() for e in result['emails'] if '@' in e
            ))
        return result
    except Exception as e:
        return {"error": str(e)}


@app.route('/whois', methods=['GET'])
def get_whois():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Paramètre 'domain' manquant"}), 400
    result = custom_whois(domain)
    if "error" in result:
        return jsonify(result), 500
    return jsonify(result)


@app.route('/docs', methods=['GET'])
def api_docs():
    return jsonify({
        "api_name": "recon-ia API",
        "version":  "2.0",
        "modules": {
            "passive": ["GET /whois"],
            "active":  ["POST /active/scan", "POST /active/authorize", "GET /active/audit"]
        },
        "endpoints": {
            "GET /whois":              "Informations WHOIS d'un domaine",
            "POST /active/scan":       "Lance un scan actif orchestré par agents IA",
            "POST /active/authorize":  "Vérifie si une cible est dans le périmètre autorisé",
            "GET /active/audit":       "Journal d'audit horodaté pour une cible"
        }
    })


# ════════════════════════════════════════════════════════════════
# NOUVELLES ROUTES — reconnaissance active (KOHOUNKO 2024-2025)
# ════════════════════════════════════════════════════════════════

@app.route('/active/authorize', methods=['POST'])
def active_authorize():
    """
    Vérifie si une cible est dans le périmètre autorisé.
    Appelé par le frontend avant tout scan pour feedback immédiat.

    Corps JSON : { "target": "172.21.0.10" }
    """
    data   = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Paramètre 'target' manquant"}), 400

    gov             = GovernanceModule()
    authorized, reason = gov.is_authorized(target)
    return jsonify({"target": target, "authorized": authorized, "reason": reason})


@app.route('/active/scan', methods=['POST'])
def active_scan():
    """
    Lance le pipeline de reconnaissance active complet.
    Appelé par le frontend ou par n8n via HTTP Request node.

    Corps JSON :
    {
        "target": "172.21.0.10",
        "passive_context": {          ← optionnel, fourni par n8n
            "open_ports": [80, 443],
            "technologies": ["Apache"]
        }
    }
    """
    data    = request.get_json(silent=True) or {}
    target  = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Paramètre 'target' manquant"}), 400

    passive_context = data.get("passive_context", {})
    report          = orchestrator.run(target, passive_context)

    result = {
        "target":          report.target,
        "timestamp_start": report.timestamp_start,
        "timestamp_end":   report.timestamp_end,
        "authorized":      report.authorized,
        "passive_context": report.passive_context,
        "masscan":         report.masscan,
        "nmap":            report.nmap,
        "analysis":        report.analysis,
        "audit_trail":     report.audit_trail,
        "error":           report.error
    }
    return jsonify(result), (200 if report.authorized and not report.error else 403)


@app.route('/active/audit', methods=['GET'])
def active_audit():
    """
    Retourne le journal d'audit complet pour une cible.
    Paramètre GET : ?target=172.21.0.10
    """
    target = request.args.get("target", "").strip()
    if not target:
        return jsonify({"error": "Paramètre 'target' manquant"}), 400

    gov   = GovernanceModule()
    trail = gov.get_trail(target)
    return jsonify({"target": target, "total": len(trail), "entries": trail})


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8000)
