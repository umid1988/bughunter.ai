#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║          HunterAI - Bug Bounty Recon Tool v1.0            ║
║     Shodan + CVE + AI tahlil | Linux CLI Tool             ║
╚═══════════════════════════════════════════════════════════╝

O'rnatish:
    pip install shodan requests rich click anthropic

Ishlatish:
    python hunter_ai.py --help
    python hunter_ai.py scan --domain example.com
    python hunter_ai.py cve --ip 1.2.3.4
    python hunter_ai.py hunt --query 'product:"Grafana" hostname:*.edu'
    python hunter_ai.py full --domain example.com --ai
"""

import os
import sys
import json
import time
import socket
import requests
import click
from datetime import datetime

try:
    import shodan
except ImportError:
    print("[!] Shodan kutubxonasi topilmadi. O'rnating: pip install shodan")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.text import Text
    from rich import box
    from rich.columns import Columns
    from rich.rule import Rule
except ImportError:
    print("[!] Rich kutubxonasi topilmadi. O'rnating: pip install rich")
    sys.exit(1)

console = Console()

# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────
BANNER = """
[bold cyan]
██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗      █████╗ ██╗
██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗    ██╔══██╗██║
███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝    ███████║██║
██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗    ██╔══██║██║
██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║    ██║  ██║██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝
[/bold cyan]
[dim]       Bug Bounty Recon Tool v1.0 | Shodan + CVE + AI tahlil[/dim]
[yellow]       ⚠️  Faqat ruxsat berilgan va qonuniy maqsadlar uchun![/yellow]
"""

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
CONFIG_FILE = os.path.expanduser("~/.hunterai_config.json")

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

def get_api_key(name):
    config = load_config()
    return config.get(name) or os.environ.get(name.upper())

# ─────────────────────────────────────────────
# SHODAN MODULE
# ─────────────────────────────────────────────
def get_shodan_client():
    api_key = get_api_key("shodan_api_key")
    if not api_key:
        console.print("[red][!] Shodan API kaliti topilmadi![/red]")
        console.print("[yellow]    Sozlash: python hunter_ai.py config --shodan YOUR_KEY[/yellow]")
        sys.exit(1)
    return shodan.Shodan(api_key)

def domain_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def find_subdomains(domain):
    """Shodan orqali subdomainlarni topish"""
    api = get_shodan_client()
    results = []
    try:
        query = f"hostname:{domain}"
        search = api.search(query, limit=100)
        for match in search.get("matches", []):
            for hostname in match.get("hostnames", []):
                results.append({
                    "hostname": hostname,
                    "ip": match.get("ip_str", ""),
                    "port": match.get("port", ""),
                    "org": match.get("org", "N/A"),
                    "country": match.get("location", {}).get("country_name", "N/A"),
                })
    except shodan.APIError as e:
        console.print(f"[red][!] Shodan xatosi: {e}[/red]")
    return results

def scan_host(ip):
    """IP bo'yicha to'liq ma'lumot"""
    api = get_shodan_client()
    try:
        return api.host(ip)
    except shodan.APIError as e:
        console.print(f"[red][!] Host ma'lumoti olishda xato: {e}[/red]")
        return None

def custom_query(query, limit=100):
    """Maxsus Shodan query"""
    api = get_shodan_client()
    try:
        return api.search(query, limit=limit)
    except shodan.APIError as e:
        console.print(f"[red][!] Query xatosi: {e}[/red]")
        return None

# ─────────────────────────────────────────────
# CVE MODULE
# ─────────────────────────────────────────────
def check_cve(ip):
    """IP bo'yicha CVE zaifliklarini tekshirish"""
    host_data = scan_host(ip)
    if not host_data:
        return []

    vulns = host_data.get("vulns", {})
    results = []
    # Shodan ba'zan `vulns` ni dict, ba'zan list ko'rinishida qaytarishi mumkin.
    if isinstance(vulns, list):
        vuln_items = [(cve_id, {}) for cve_id in vulns]
    elif isinstance(vulns, dict):
        vuln_items = vulns.items()
    else:
        vuln_items = []

    for cve_id, info in vuln_items:
        if not isinstance(info, dict):
            info = {}
        cvss = info.get("cvss", 0)
        severity = "CRITICAL" if cvss >= 9.0 else \
                   "HIGH" if cvss >= 7.0 else \
                   "MEDIUM" if cvss >= 4.0 else "LOW"
        results.append({
            "cve": cve_id,
            "cvss": cvss,
            "severity": severity,
            "summary": info.get("summary", "N/A")[:100],
            "verified": info.get("verified", False),
        })
    results.sort(key=lambda x: x["cvss"], reverse=True)
    return results

def fetch_cve_details(cve_id):
    """CVEDB API dan batafsil ma'lumot (bepul)"""
    try:
        r = requests.get(f"https://cvedb.shodan.io/cve/{cve_id}", timeout=10)
        return r.json()
    except Exception:
        return {}

# ─────────────────────────────────────────────
# CREDENTIAL HUNTER MODULE
# ─────────────────────────────────────────────
CREDENTIAL_QUERIES = [
    ('Admin panellar', 'http.title:"Admin Panel"'),
    ('Grafana', 'product:"Grafana"'),
    ('Jenkins', 'product:"Jenkins"'),
    ('Kibana', 'product:"Kibana"'),
    ('MongoDB ochiq', 'product:"MongoDB" -authentication'),
    ('Elasticsearch', 'product:"Elasticsearch"'),
    ('phpMyAdmin', 'http.title:"phpMyAdmin"'),
    ('Default login', 'http.title:"Login" http.html:"admin"'),
    ('RDP ochiq', 'port:3389'),
    ('FTP anonymous', 'ftp.features:"Anonymous"'),
]

def credential_hunt(domain=None, custom_q=None):
    """Credential va ochiq xizmatlarni topish"""
    api = get_shodan_client()
    found = []

    queries = [(custom_q, custom_q)] if custom_q else CREDENTIAL_QUERIES

    for name, query in queries:
        if domain:
            query = f"{query} hostname:{domain}"
        try:
            results = api.search(query, limit=20)
            for match in results.get("matches", []):
                found.append({
                    "type": name,
                    "ip": match.get("ip_str", ""),
                    "port": match.get("port", ""),
                    "hostname": ", ".join(match.get("hostnames", [])[:2]) or "N/A",
                    "org": match.get("org", "N/A"),
                    "country": match.get("location", {}).get("country_name", "N/A"),
                })
            time.sleep(0.5)
        except shodan.APIError:
            continue
    return found

# ─────────────────────────────────────────────
# AI TAHLIL MODULE
# ─────────────────────────────────────────────
def ai_analyze(data, analysis_type="general"):
    """Claude AI orqali tahlil"""
    api_key = get_api_key("anthropic_api_key")
    if not api_key:
        console.print("[yellow][!] Anthropic API kaliti yo'q. AI tahlil o'tkazib yuboriladi.[/yellow]")
        console.print("[dim]    Sozlash: python hunter_ai.py config --anthropic YOUR_KEY[/dim]")
        return None

    prompts = {
        "cve": f"""Sen bug bounty expert mutaxassisisas. 
Quyidagi CVE zaifliklarni tahlil qil va bug bounty uchun eng foydalilarini ajrat:

{json.dumps(data, indent=2, ensure_ascii=False)}

Quyidagilarni ko'rsat:
1. Eng yuqori prioritetli 3 ta zaiflik va sababi
2. Har biri uchun exploit yo'nalishi
3. Bug bounty reportida nima yozish kerak
4. CVSS balini hisobga olib jiddiylik darajasi

Uzbek tilida javob ber.""",

        "credential": f"""Sen bug bounty expert mutaxassisisas.
Quyidagi ochiq xizmatlar va credential topilmalarni tahlil qil:

{json.dumps(data, indent=2, ensure_ascii=False)}

Quyidagilarni ko'rsat:
1. Eng xavfli topilmalar
2. Har biri uchun tekshirish usuli
3. Bug bounty uchun qiymati (High/Medium/Low)
4. Keyingi qadamlar

Uzbek tilida javob ber.""",

        "general": f"""Sen bug bounty expert mutaxassisisas.
Quyidagi scan natijalarini tahlil qil:

{json.dumps(data, indent=2, ensure_ascii=False)}

Quyidagilarni ko'rsat:
1. Umumiy xavfsizlik holati
2. Eng muhim topilmalar
3. Bug bounty uchun tavsiyalar
4. Keyingi tekshiruv yo'nalishlari

Uzbek tilida javob ber."""
    }

    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 1500,
                "messages": [{"role": "user", "content": prompts.get(analysis_type, prompts["general"])}]
            },
            timeout=30
        )
        if r.status_code != 200:
            console.print(f"[red][!] AI API xatosi: HTTP {r.status_code}[/red]")
            return None

        data_resp = r.json()
        content = data_resp.get("content", [])
        if not content or not isinstance(content, list):
            console.print("[red][!] AI javobi noto'g'ri formatda qaytdi[/red]")
            return None
        first_block = content[0] if content else {}
        return first_block.get("text")
    except Exception as e:
        console.print(f"[red][!] AI tahlil xatosi: {e}[/red]")
        return None

# ─────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────
def severity_color(severity):
    return {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }.get(severity, "white")

def print_subdomains(results):
    if not results:
        console.print("[yellow][!] Subdomain topilmadi[/yellow]")
        return
    table = Table(title=f"🌐 Topilgan Subdomainlar ({len(results)} ta)", box=box.ROUNDED, border_style="cyan")
    table.add_column("Hostname", style="cyan", no_wrap=True)
    table.add_column("IP", style="green")
    table.add_column("Port", style="yellow")
    table.add_column("Org", style="white")
    table.add_column("Mamlakat", style="dim")
    for r in results[:50]:
        table.add_row(r["hostname"], r["ip"], str(r["port"]), r["org"][:30], r["country"])
    console.print(table)

def print_cve_results(results, ip):
    if not results:
        console.print(f"[green][+] {ip} uchun CVE zaiflik topilmadi[/green]")
        return
    table = Table(title=f"🔴 CVE Zaifliklar - {ip} ({len(results)} ta)", box=box.ROUNDED, border_style="red")
    table.add_column("CVE ID", style="bold", no_wrap=True)
    table.add_column("CVSS", justify="center")
    table.add_column("Daraja", justify="center")
    table.add_column("Tasdiqlangan", justify="center")
    table.add_column("Tavsif", style="dim")
    for r in results:
        color = severity_color(r["severity"])
        verified = "✅" if r["verified"] else "❓"
        table.add_row(
            f"[bold]{r['cve']}[/bold]",
            f"[{color}]{r['cvss']}[/{color}]",
            f"[{color}]{r['severity']}[/{color}]",
            verified,
            r["summary"]
        )
    console.print(table)

def print_credentials(results):
    if not results:
        console.print("[green][+] Ochiq credential topilmadi[/green]")
        return
    table = Table(title=f"🔑 Credential Topilmalar ({len(results)} ta)", box=box.ROUNDED, border_style="yellow")
    table.add_column("Tur", style="yellow")
    table.add_column("IP", style="green")
    table.add_column("Port", style="cyan")
    table.add_column("Hostname", style="white")
    table.add_column("Tashkilot", style="dim")
    table.add_column("Mamlakat", style="dim")
    for r in results[:50]:
        table.add_row(r["type"], r["ip"], str(r["port"]), r["hostname"][:30], r["org"][:25], r["country"])
    console.print(table)

def save_report(data, filename):
    """JSON formatda hisobot saqlash"""
    report = {
        "timestamp": datetime.now().isoformat(),
        "tool": "HunterAI v1.0",
        "data": data
    }
    with open(filename, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    console.print(f"\n[green][+] Hisobot saqlandi: {filename}[/green]")

# ─────────────────────────────────────────────
# CLI COMMANDS
# ─────────────────────────────────────────────
@click.group()
def cli():
    """HunterAI - Bug Bounty Recon Tool\n\nMisol: python hunter_ai.py scan --domain example.com"""
    console.print(BANNER)

@cli.command()
@click.option("--shodan", "shodan_key", help="Shodan API kaliti")
@click.option("--anthropic", "anthropic_key", help="Anthropic API kaliti")
def config(shodan_key, anthropic_key):
    """API kalitlarini sozlash"""
    cfg = load_config()
    if shodan_key:
        cfg["shodan_api_key"] = shodan_key
        console.print("[green][+] Shodan API kaliti saqlandi[/green]")
    if anthropic_key:
        cfg["anthropic_api_key"] = anthropic_key
        console.print("[green][+] Anthropic API kaliti saqlandi[/green]")
    if not shodan_key and not anthropic_key:
        console.print("[yellow]Mavjud sozlamalar:[/yellow]")
        for k, v in cfg.items():
            v_str = str(v)
            masked = v_str[:6] + "..." + v_str[-4:] if len(v_str) > 10 else "***"
            console.print(f"  {k}: {masked}")
        return
    save_config(cfg)

@cli.command()
@click.option("--domain", required=True, help="Tekshiriladigan domen (masalan: example.com)")
@click.option("--ai", is_flag=True, help="AI tahlilni yoqish")
@click.option("--output", help="Natijani faylga saqlash (masalan: result.json)")
def scan(domain, ai, output):
    """Domen bo'yicha subdomain topish"""
    console.print(Rule(f"[cyan]🔍 Scanning: {domain}[/cyan]"))

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
        task = p.add_task(f"Subdomainlar qidirilmoqda: {domain}...", total=None)
        results = find_subdomains(domain)
        p.update(task, completed=True)

    print_subdomains(results)

    if ai and results:
        console.print(Rule("[yellow]🤖 AI Tahlil[/yellow]"))
        with Progress(SpinnerColumn(), TextColumn("[yellow]Claude tahlil qilmoqda..."), transient=True) as p:
            p.add_task("", total=None)
            analysis = ai_analyze(results[:20], "general")
        if analysis:
            console.print(Panel(analysis, title="[yellow]AI Tahlil Natijasi[/yellow]", border_style="yellow"))

    if output:
        save_report({"domain": domain, "subdomains": results}, output)

@cli.command()
@click.option("--ip", required=True, help="Tekshiriladigan IP manzil")
@click.option("--ai", is_flag=True, help="AI tahlilni yoqish")
@click.option("--output", help="Natijani faylga saqlash")
def cve(ip, ai, output):
    """IP manzil bo'yicha CVE zaifliklarini tekshirish"""
    console.print(Rule(f"[red]🔴 CVE Scan: {ip}[/red]"))

    with Progress(SpinnerColumn(), TextColumn("[red]{task.description}"), transient=True) as p:
        p.add_task(f"CVE tekshirilmoqda: {ip}...", total=None)
        results = check_cve(ip)

    print_cve_results(results, ip)

    if ai and results:
        console.print(Rule("[yellow]🤖 AI Tahlil[/yellow]"))
        with Progress(SpinnerColumn(), TextColumn("[yellow]Claude CVE tahlil qilmoqda..."), transient=True) as p:
            p.add_task("", total=None)
            analysis = ai_analyze(results, "cve")
        if analysis:
            console.print(Panel(analysis, title="[yellow]CVE AI Tahlili[/yellow]", border_style="yellow"))

    if output:
        save_report({"ip": ip, "cves": results}, output)

@cli.command()
@click.option("--domain", help="Domen bo'yicha filtrlash (ixtiyoriy)")
@click.option("--query", help="Maxsus Shodan query")
@click.option("--ai", is_flag=True, help="AI tahlilni yoqish")
@click.option("--output", help="Natijani faylga saqlash")
def hunt(domain, query, ai, output):
    """Credential va ochiq xizmatlarni topish"""
    console.print(Rule("[yellow]🔑 Credential Hunt[/yellow]"))

    with Progress(SpinnerColumn(), TextColumn("[yellow]{task.description}"), transient=True) as p:
        p.add_task("Ochiq xizmatlar qidirilmoqda...", total=None)
        results = credential_hunt(domain=domain, custom_q=query)

    print_credentials(results)

    if ai and results:
        console.print(Rule("[yellow]🤖 AI Tahlil[/yellow]"))
        with Progress(SpinnerColumn(), TextColumn("[yellow]Claude tahlil qilmoqda..."), transient=True) as p:
            p.add_task("", total=None)
            analysis = ai_analyze(results[:20], "credential")
        if analysis:
            console.print(Panel(analysis, title="[yellow]Credential AI Tahlili[/yellow]", border_style="yellow"))

    if output:
        save_report({"domain": domain, "credentials": results}, output)

@cli.command()
@click.option("--query", required=True, help="Shodan query (masalan: 'product:\"Grafana\" hostname:*.edu')")
@click.option("--limit", default=100, help="Natijalar soni (default: 100)")
@click.option("--output", help="Natijani faylga saqlash")
def search(query, limit, output):
    """Maxsus Shodan query bajarish"""
    console.print(Rule(f"[cyan]🔎 Query: {query}[/cyan]"))

    with Progress(SpinnerColumn(), TextColumn("[cyan]Qidirilmoqda..."), transient=True) as p:
        p.add_task("", total=None)
        results = custom_query(query, limit)

    if not results:
        return

    total = results.get("total", 0)
    matches = results.get("matches", [])

    console.print(f"\n[green][+] Jami natija: {total} ta[/green]")

    # Top domenlar
    from collections import Counter
    domains = []
    ports = []
    for m in matches:
        domains.extend(m.get("hostnames", []))
        ports.append(m.get("port"))

    if domains:
        table = Table(title="Top Domenlar", box=box.SIMPLE, border_style="cyan")
        table.add_column("Domen", style="cyan")
        table.add_column("Son", style="yellow", justify="right")
        for domain, count in Counter(domains).most_common(10):
            table.add_row(domain, str(count))
        console.print(table)

    if ports:
        table2 = Table(title="Top Portlar", box=box.SIMPLE, border_style="green")
        table2.add_column("Port", style="green")
        table2.add_column("Son", style="yellow", justify="right")
        for port, count in Counter(ports).most_common(10):
            table2.add_row(str(port), str(count))
        console.print(table2)

    if output:
        save_report({"query": query, "total": total, "matches": matches[:50]}, output)

@cli.command()
@click.option("--domain", required=True, help="To'liq scan uchun domen")
@click.option("--ai", is_flag=True, help="AI tahlilni yoqish")
@click.option("--output", help="Natijani faylga saqlash")
def full(domain, ai, output):
    """To'liq rekon: subdomain + CVE + credential + AI"""
    console.print(Panel(
        f"[bold cyan]To'liq Rekon Boshlandi[/bold cyan]\n[dim]Domen: {domain}[/dim]",
        border_style="cyan"
    ))

    all_data = {"domain": domain, "timestamp": datetime.now().isoformat()}

    # 1. Subdomainlar
    console.print(Rule("[cyan]1/3 — Subdomain Topish[/cyan]"))
    with Progress(SpinnerColumn(), TextColumn("[cyan]Subdomainlar..."), transient=True) as p:
        p.add_task("", total=None)
        subdomains = find_subdomains(domain)
    print_subdomains(subdomains)
    all_data["subdomains"] = subdomains

    # 2. CVE tekshiruv (asosiy IP uchun)
    console.print(Rule("[red]2/3 — CVE Tekshiruv[/red]"))
    ip = domain_to_ip(domain)
    cve_results = []
    if ip:
        console.print(f"[dim]IP: {ip}[/dim]")
        with Progress(SpinnerColumn(), TextColumn("[red]CVE tekshirilmoqda..."), transient=True) as p:
            p.add_task("", total=None)
            cve_results = check_cve(ip)
        print_cve_results(cve_results, ip)
    else:
        console.print("[yellow][!] IP topilmadi[/yellow]")
    all_data["cves"] = cve_results

    # 3. Credential hunt
    console.print(Rule("[yellow]3/3 — Credential Hunt[/yellow]"))
    with Progress(SpinnerColumn(), TextColumn("[yellow]Ochiq xizmatlar..."), transient=True) as p:
        p.add_task("", total=None)
        creds = credential_hunt(domain=domain)
    print_credentials(creds)
    all_data["credentials"] = creds

    # 4. AI tahlil
    if ai:
        console.print(Rule("[magenta]🤖 Umumiy AI Tahlil[/magenta]"))
        summary = {
            "subdomains_count": len(subdomains),
            "cves": cve_results[:5],
            "credentials_count": len(creds),
            "credentials_sample": creds[:5],
        }
        with Progress(SpinnerColumn(), TextColumn("[magenta]Claude tahlil qilmoqda..."), transient=True) as p:
            p.add_task("", total=None)
            analysis = ai_analyze(summary, "general")
        if analysis:
            console.print(Panel(analysis, title="[magenta]AI Xulosasi[/magenta]", border_style="magenta"))
        all_data["ai_analysis"] = analysis

    # Xulosa
    console.print(Rule("[green]✅ Xulosa[/green]"))
    stats = Table(box=box.SIMPLE, show_header=False)
    stats.add_column("", style="dim")
    stats.add_column("", style="bold green")
    stats.add_row("Subdomainlar:", str(len(subdomains)))
    stats.add_row("CVE zaifliklar:", str(len(cve_results)))
    critical = sum(1 for c in cve_results if c["severity"] == "CRITICAL")
    stats.add_row("Critical CVE:", f"[red]{critical}[/red]")
    stats.add_row("Ochiq xizmatlar:", str(len(creds)))
    console.print(stats)

    if output:
        save_report(all_data, output)

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    cli()
