import re
import ssl
import socket
import datetime
from urllib.parse import urlparse

VIRUSTOTAL_API_KEY = "9e72fcacb492ab8080ee91b880b625c556e8904bf5829d8559ab73457e02951c"
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyADG-MX7Ev1eTgM8CROY-FmCDzZyn0SSlg"

# Palavras suspeitas comuns em URLs de phishing
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "banking", "confirm", "password", "signin", "wallet",
    "support", "alert", "suspended", "unlock", "validate"
]

# Domínios legítimos comuns para detectar typosquatting
KNOWN_BRANDS = [
    "paypal", "amazon", "google", "facebook", "instagram",
    "microsoft", "apple", "netflix", "banco", "bradesco",
    "itau", "nubank", "mercadolivre", "correios"
]


# ─────────────────────────────────────────
# CAMADA 1 — BLACKLISTS (peso máx: 40 pts)
# ─────────────────────────────────────────
def check_virustotal(url: str) -> dict:
    """Consulta o VirusTotal e retorna score baseado nos engines que detectaram."""
    try:
        import requests
        import base64

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=5
        )

        if response.status_code != 200:
            return {"score": 0, "detail": "VirusTotal indisponível ou URL não encontrada"}

        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)

        if malicious == 0:
            return {"score": 0, "detail": f"VirusTotal: limpa (0 engines)"}
        elif malicious <= 5:
            return {"score": 15, "detail": f"VirusTotal: {malicious} engines detectaram ameaça"}
        elif malicious <= 20:
            return {"score": 30, "detail": f"VirusTotal: {malicious} engines detectaram ameaça"}
        else:
            return {"score": 40, "detail": f"VirusTotal: {malicious} engines detectaram ameaça — alto risco"}

    except Exception as e:
        return {"score": 0, "detail": f"Erro ao consultar VirusTotal: {str(e)}"}


def check_google_safe_browsing(url: str) -> dict:
    """Consulta a API do Google Safe Browsing."""
    try:
        import requests

        payload = {
            "client": {"clientId": "url-checker", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}",
            json=payload,
            timeout=5
        )

        data = response.json()
        if data.get("matches"):
            threat = data["matches"][0]["threatType"]
            return {"score": 40, "detail": f"Google Safe Browsing: detectou {threat}"}

        return {"score": 0, "detail": "Google Safe Browsing: URL limpa"}

    except Exception as e:
        return {"score": 0, "detail": f"Erro ao consultar Google Safe Browsing: {str(e)}"}


# ─────────────────────────────────────────
# CAMADA 2 — HEURÍSTICA DA URL (peso máx: 25 pts)
# ─────────────────────────────────────────
def check_heuristics(url: str) -> dict:
    score = 0
    details = []
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    full_url = url.lower()

    # IP no lugar de domínio
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$")
    if ip_pattern.match(domain):
        score += 15
        details.append("IP usado como domínio (+15)")

    # Typosquatting
    for brand in KNOWN_BRANDS:
        if brand in domain:
            # Verifica se não é o domínio legítimo exato
            if not domain.startswith(brand + ".") and not domain == brand + ".com" and not domain == brand + ".com.br":
                score += 10
                details.append(f"Possível typosquatting de '{brand}' (+10)")
                break

    # Excesso de subdomínios
    subdomains = domain.split(".")
    if len(subdomains) > 4:
        score += 8
        details.append(f"Excesso de subdomínios: {len(subdomains)} (+8)")

    # Palavras-chave suspeitas
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in full_url:
            score += 5
            details.append(f"Palavra suspeita encontrada: '{keyword}' (+5)")
            break  # conta só uma vez

    # URL muito longa
    if len(url) > 100:
        score += 3
        details.append(f"URL muito longa: {len(url)} caracteres (+3)")

    # Caracteres suspeitos (excesso de hífens, @, etc)
    if url.count("-") > 4:
        score += 2
        details.append("Excesso de hífens na URL (+2)")

    if "@" in domain:
        score += 5
        details.append("Símbolo @ no domínio — técnica de spoofing (+5)")

    score = min(score, 25)  # limita ao peso máximo da camada
    return {
        "score": score,
        "detail": details if details else ["Heurística: nenhum padrão suspeito detectado"]
    }


# ─────────────────────────────────────────
# CAMADA 3 — WHOIS / IDADE DO DOMÍNIO (peso máx: 20 pts)
# ─────────────────────────────────────────
def check_whois(url: str) -> dict:
    try:
        import whois
        parsed = urlparse(url)
        domain = parsed.netloc

        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return {"score": 5, "detail": "WHOIS: data de criação não disponível (leve suspeita)"}

        age_days = (datetime.datetime.now() - creation_date).days

        if age_days < 7:
            return {"score": 20, "detail": f"WHOIS: domínio criado há {age_days} dias — muito recente (+20)"}
        elif age_days < 30:
            return {"score": 15, "detail": f"WHOIS: domínio criado há {age_days} dias (+15)"}
        elif age_days < 90:
            return {"score": 8, "detail": f"WHOIS: domínio criado há {age_days} dias (+8)"}
        else:
            return {"score": 0, "detail": f"WHOIS: domínio com {age_days} dias — considerado estabelecido"}

    except Exception as e:
        return {"score": 0, "detail": f"WHOIS: não foi possível verificar ({str(e)})"}


# ─────────────────────────────────────────
# CAMADA 4 — SSL / HTTPS (peso máx: 15 pts)
# ─────────────────────────────────────────
def check_ssl(url: str) -> dict:
    parsed = urlparse(url)

    # Sem HTTPS
    if parsed.scheme != "https":
        return {"score": 15, "detail": "SSL: site sem HTTPS (+15)"}

    domain = parsed.netloc.split(":")[0]

    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain
        )
        conn.settimeout(5)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()

        # Verifica expiração
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_date = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            if expire_date < datetime.datetime.now():
                return {"score": 10, "detail": "SSL: certificado expirado (+10)"}

        return {"score": 0, "detail": "SSL: certificado válido e HTTPS ativo"}

    except ssl.SSLCertVerificationError:
        return {"score": 8, "detail": "SSL: certificado inválido ou autoassinado (+8)"}
    except Exception as e:
        return {"score": 5, "detail": f"SSL: não foi possível verificar ({str(e)})"}


# ─────────────────────────────────────────
# ORQUESTRADOR PRINCIPAL
# ─────────────────────────────────────────
def get_verdict(score: int) -> dict:
    if score <= 30:
        return {"level": "SEGURO", "emoji": "✅", "color": "green"}
    elif score <= 60:
        return {"level": "SUSPEITO", "emoji": "⚠️", "color": "yellow"}
    else:
        return {"level": "MALICIOSO", "emoji": "🚨", "color": "red"}


def get_certainty(layers_triggered: int) -> str:
    if layers_triggered >= 3:
        return "ALTA"
    elif layers_triggered == 2:
        return "MÉDIA"
    else:
        return "BAIXA"


def analyze_url(url: str) -> dict:
    """Orquestra todas as camadas e retorna o resultado final."""

    # Executa todas as camadas
    virustotal = check_virustotal(url)
    google = check_google_safe_browsing(url)
    heuristics = check_heuristics(url)
    whois_result = check_whois(url)
    ssl_result = check_ssl(url)

    # Calcula score total
    total_score = (
        virustotal["score"] +
        google["score"] +
        heuristics["score"] +
        whois_result["score"] +
        ssl_result["score"]
    )
    total_score = min(total_score, 100)

    # Conta camadas que sinalizaram
    layers_triggered = sum([
        1 for layer in [virustotal, google, heuristics, whois_result, ssl_result]
        if layer["score"] > 0
    ])

    verdict = get_verdict(total_score)
    certainty = get_certainty(layers_triggered)

    return {
        "url": url,
        "score": total_score,
        "verdict": verdict["level"],
        "emoji": verdict["emoji"],
        "certainty": certainty,
        "layers": {
            "blacklist_virustotal": virustotal,
            "blacklist_google": google,
            "heuristics": heuristics,
            "whois": whois_result,
            "ssl": ssl_result
        }
    }
