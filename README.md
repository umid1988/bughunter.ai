# HunterAI - Bug Bounty Recon Tool v1.0
> Shodan + CVE + AI tahlil | Linux CLI Tool

---

## O'rnatish

```bash
# 1. Kutubxonalarni o'rnatish
pip install shodan requests rich click anthropic

# 2. Faylni ishga tayyor qilish
chmod +x hunter_ai.py

# 3. API kalitlarini sozlash
python hunter_ai.py config --shodan YOUR_SHODAN_KEY
python hunter_ai.py config --anthropic YOUR_ANTHROPIC_KEY
```

---

## Ishlatish

### 1. Subdomain topish
```bash
python hunter_ai.py scan --domain example.com
python hunter_ai.py scan --domain example.com --ai              # AI tahlil bilan
python hunter_ai.py scan --domain example.com --output out.json # Saqlash
```

### 2. CVE tekshiruv
```bash
python hunter_ai.py cve --ip 1.2.3.4
python hunter_ai.py cve --ip 1.2.3.4 --ai
```

### 3. Credential hunt
```bash
python hunter_ai.py hunt --domain example.com
python hunter_ai.py hunt --query 'product:"Grafana" hostname:*.edu'
python hunter_ai.py hunt --domain example.com --ai
```

### 4. Maxsus query (ShodanHunter kabi)
```bash
python hunter_ai.py search --query 'product:"Grafana" hostname:*.edu'
python hunter_ai.py search --query 'http.title:"Admin Panel"' --limit 50
```

### 5. To'liq rekon (hammasi birga)
```bash
python hunter_ai.py full --domain example.com --ai --output report.json
```

---

## Komandalar

| Komanda | Tavsif |
|---------|--------|
| `config` | API kalitlarini sozlash |
| `scan`   | Subdomain topish |
| `cve`    | CVE zaiflik tekshiruv |
| `hunt`   | Credential va ochiq xizmatlar |
| `search` | Maxsus Shodan query |
| `full`   | To'liq rekon |

---

## ⚠️ Ogohlantirish
Faqat ruxsat berilgan va qonuniy maqsadlar uchun ishlating!
