#!/usr/bin/env python3
"""
VulnCheck - Cross-platform vulnerability posture (Windows/Linux)
• Rich checks + interactive HTML report (dark/light, donut score, filters)
• Stable, bounded scoring (diminishing-returns model)
Outputs: report.html, findings.csv, debug.json
"""

import os, sys, platform, csv, json, datetime, socket, webbrowser, traceback
from pathlib import Path

import checks_windows, checks_linux

def detect_platform():
    sysplat = platform.system().lower()
    if "windows" in sysplat: return "windows"
    if "linux"   in sysplat: return "linux"
    return sysplat

def compute_overall_score(findings):
    """
    Bounded scoring with diminishing returns.
    Each finding subtracts points based on severity, but stacking is softened
    after 60 penalty points to avoid instant 0 scores.
    """
    base_weights = {"Critical": 35, "High": 20, "Medium": 8, "Low": 2}

    # raw penalty from all findings
    penalty = sum(base_weights.get(f.get("severity", "Low"), 2) for f in findings)

    # soften impact once penalty > 60
    if penalty > 60:
        penalty = 60 + 0.5 * (penalty - 60)

    # cap at 100
    penalty = min(100, penalty)

    return max(0, int(100 - penalty))

def pick_top_recommendations(findings, limit=5):
    seen, recos = set(), []
    for f in sorted(findings, key=lambda x: x.get("cvss", 0.0), reverse=True):
        r = f.get("remediation", "").strip()
        if r and r not in seen:
            seen.add(r); recos.append(r)
        if len(recos) >= limit: break
    return recos or ["No critical issues detected. Maintain regular updates and backups."]

def render_report(context):
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    tpl_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(tpl_dir)),
                      autoescape=select_autoescape(['html','xml']))
    tpl = env.get_template("report.html.j2")
    html = tpl.render(**context)
    with open("report.html","w",encoding="utf-8") as f:
        f.write(html)

def write_csv(host, findings):
    with open("findings.csv","w",newline='',encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host","os","timestamp","id","title","severity","cvss","remediation","evidence"])
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        for fi in findings:
            w.writerow([host["hostname"], host["os"], ts,
                        fi.get("id",""), fi.get("title",""), fi.get("severity",""),
                        fi.get("cvss",""), fi.get("remediation",""), fi.get("evidence","")])

def group_by_sev(findings):
    g = {"Critical":[], "High":[], "Medium":[], "Low":[]}
    for f in findings:
        g.setdefault(f["severity"], []).append(f)
    return g

def main():
    hostname = socket.gethostname()
    plat = detect_platform()
    host = {"hostname": hostname, "os": plat, "detail": ""}

    try:
        if plat == "windows":
            raw = checks_windows.gather()
            host["detail"] = (raw.get("os_detail") or "")[:160]
            findings = checks_windows.analyze(raw)
        elif plat == "linux":
            raw = checks_linux.gather()
            host["detail"] = raw.get("os_detail","")
            findings = checks_linux.analyze(raw)
        else:
            raw = {"platform": sys.platform}
            findings = [{
                "id":"UNSUPPORTED","title":f"Unsupported platform: {plat}",
                "cvss":0.0,"severity":"Low",
                "remediation":"Run on Windows or Linux systems.",
                "evidence": sys.platform
            }]
    except Exception:
        raw = {"error": "runtime exception"}
        findings = [{
            "id":"RUNTIME-ERROR","title":"Runtime error while gathering checks",
            "cvss":0.0,"severity":"Low",
            "remediation":"Inspect debug.json; run with Admin/sudo if needed.",
            "evidence": traceback.format_exc()
        }]

    # Save raw debug
    with open("debug.json","w",encoding="utf-8") as f:
        json.dump(raw, f, indent=2)

    # Counts & score
    counts = {"Critical":0,"High":0,"Medium":0,"Low":0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"],0) + 1

    score = compute_overall_score(findings)

    # Build context for template
    context = {
        "host": host,
        "findings": findings,
        "by_sev": group_by_sev(findings),
        "counts": counts,
        "summary": {
            "score": score,
            "summary_text": "Address Critical/High items first; lower score means higher risk."
        },
        "top_recos": pick_top_recommendations(findings),
        "meta": {"generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}
    }

    write_csv(host, findings)
    render_report(context)

    try:
        import webbrowser
        import os

        report_path = os.path.abspath("report.html")
        webbrowser.open_new_tab(report_path)
    except Exception:
        pass

    print(f"[OK] Generated report.html and findings.csv (Overall Score: {score}/100)")

if __name__ == "__main__":
    main()