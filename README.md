<div align="center">

# 🕵️ HunterAI - Bug Bounty Recon Tool v1.0

[![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-Educational-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux)](https://linux.org)
[![Shodan](https://img.shields.io/badge/Powered%20by-Shodan-red?style=for-the-badge)](https://shodan.io)

> **Shodan + CVE + AI tahlil | Linux CLI Tool**
> 
> Bug Bounty uchun avtomatik razvedka vositasi

</div>

---

## ✨ Imkoniyatlar

- 🔍 **Subdomain topish** — Shodan orqali domenlar skanerlash
- 🛡️ **CVE tekshiruv** — IP bo'yicha zaifliklarni aniqlash
- 🔑 **Credential hunt** — Ochiq xizmatlar va credentials topish
- 🤖 **AI tahlil** — Claude AI orqali natijalarni tahlil qilish
- 📊 **Hisobot** — JSON formatda saqlash

---

## ⚙️ O'rnatish

```bash
# 1. Reponi klonlash
git clone https://github.com/umid1988/bughunter.ai.git
cd bughunter.ai

# 2. Kutubxonalarni o'rnatish
pip install -r requirements.txt

# 3. Faylni ishga tayyor qilish
chmod +x hunter_ai.py

# 4. API kalitlarini sozlash
python hunter_ai.py config --shodan YOUR_SHODAN_KEY
python hunter_ai.py config --anthropic YOUR_ANTHROPIC_KEY
```

---

## 🚀 Ishlatish

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

### 4. Maxsus Shodan query
```bash
python hunter_ai.py search --query 'product:"Grafana" hostname:*.edu'
python hunter_ai.py search --query 'http.title:"Admin Panel"' --limit 50
```

### 5. To'liq rekon (hammasi birga)
```bash
python hunter_ai.py full --domain example.com --ai --output report.json
```

---

## 📋 Komandalar

| Komanda | Tavsif |
|---------|--------|
| `config` | API kalitlarini sozlash |
| `scan` | Subdomain topish |
| `cve` | CVE zaiflik tekshiruv |
| `hunt` | Credential va ochiq xizmatlar |
| `search` | Maxsus Shodan query |
| `full` | To'liq rekon |

---

## 🔑 API Kalitlari

| Xizmat | Havola |
|--------|--------|
| Shodan API | [shodan.io/dashboard](https://account.shodan.io) |
| Anthropic API | [console.anthropic.com](https://console.anthropic.com) |

---

## ⚠️ Ogohlantirish

> Bu vosita **faqat ta'lim maqsadida** va **ruxsat berilgan** tizimlarda ishlatish uchun mo'ljallangan.
> 
> Ruxsatsiz tizimlarda ishlatish **qonunga xilof** va javobgarlikka tortiladi!

---

<div align="center">
Made with ❤️ by <a href="https://github.com/umid1988">umid1988</a> | Jizzax, O'zbekiston
</div>
EOF
