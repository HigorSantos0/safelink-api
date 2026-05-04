# 🔐 URL Safety Checker API

API em Python para identificação de sites maliciosos usando sistema de score por camadas.

---

## 📦 Instalação

```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuração

Antes de rodar, abra o arquivo `analyzer.py` e substitua suas chaves de API:

```python
VIRUSTOTAL_API_KEY = "SUA_CHAVE_AQUI"
GOOGLE_SAFE_BROWSING_API_KEY = "SUA_CHAVE_AQUI"
```

- **VirusTotal**: https://www.virustotal.com/gui/my-apikey (gratuito)
- **Google Safe Browsing**: https://console.cloud.google.com (gratuito)

> Mesmo sem as chaves, as camadas de Heurística, WHOIS e SSL funcionam normalmente.

---

## ▶️ Como rodar

```bash
uvicorn main:app --reload
```

A API estará disponível em: `http://localhost:8000`

Documentação automática: `http://localhost:8000/docs`

---

## 🔍 Como usar

### Endpoint principal

**POST** `/analyze`

```json
{
  "url": "http://paypa1.com.login-verify.click/account"
}
```

### Resposta esperada

```json
{
  "url": "http://paypa1.com.login-verify.click/account",
  "score": 80,
  "verdict": "MALICIOSO",
  "emoji": "🚨",
  "certainty": "ALTA",
  "layers": {
    "blacklist_virustotal": { "score": 30, "detail": "VirusTotal: 8 engines detectaram ameaça" },
    "blacklist_google":     { "score": 40, "detail": "Google Safe Browsing: detectou SOCIAL_ENGINEERING" },
    "heuristics":           { "score": 25, "detail": ["Possível typosquatting de 'paypal' (+10)", "Palavra suspeita: 'login' (+5)", ...] },
    "whois":                { "score": 20, "detail": "WHOIS: domínio criado há 3 dias — muito recente (+20)" },
    "ssl":                  { "score": 15, "detail": "SSL: site sem HTTPS (+15)" }
  }
}
```

---

## 📊 Sistema de Score

| Score    | Veredito   |
|----------|------------|
| 0 – 30   | ✅ SEGURO   |
| 31 – 60  | ⚠️ SUSPEITO |
| 61 – 100 | 🚨 MALICIOSO |

---

## 🧱 Camadas de Verificação

| Camada              | Peso Máximo | Descrição                        |
|---------------------|-------------|----------------------------------|
| VirusTotal          | 40 pts      | Blacklist com 70+ engines        |
| Google Safe Browsing| 40 pts      | Detecção de phishing e malware   |
| Heurística da URL   | 25 pts      | Análise de padrões suspeitos     |
| WHOIS               | 20 pts      | Idade e reputação do domínio     |
| SSL/HTTPS           | 15 pts      | Verificação do certificado       |
