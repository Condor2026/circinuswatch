# 🌀 CircinusWatch v8.0

**Passive OSINT & Web Security Audit**

Herramienta defensiva de reconocimiento pasivo y auditoría de seguridad web. Recopila información de fuentes públicas, audita cabeceras/TLS/cookies, extrae IOCs y correlaciona técnicas MITRE ATT&CK — todo sin generar tráfico intrusivo contra el objetivo.

> ⚠️ **Uso responsable.** Lee [DISCLAIMER.md](DISCLAIMER.md) antes de usar esta herramienta.

---

## ✨ Características

- 🕵 **OSINT pasivo** — WHOIS, DNS (MX/SPF/DMARC), crt.sh, Wayback, favicon hash, geolocalización IP.
- 🔒 **Auditoría web** — cabeceras de seguridad, TLS/certificado, cookies, divulgación de versión.
- 🦠 **Detección de firmas** — patrones de malware/obfuscación en HTML (estático, sin ejecución).
- 📌 **Extracción de IOCs** — IPs, dominios, URLs y hashes del contenido público (nunca contactados).
- 🎯 **MITRE ATT&CK** — correlación pasiva de hallazgos.
- 📡 **Threat intel opcional** — VirusTotal, URLHaus, Google Safe Browsing, AbuseIPDB, GreyNoise, Shodan.
- 🗣 **Análisis narrativo simétrico** — cuenta marcadores de encuadre beligerante/emocional **en todas las direcciones** (prorruso, proucraniano, pro-OTAN, anti-OTAN). **No es un veredicto.**
- 📊 **Dashboard local** — Flask en `127.0.0.1:5000`.
- 📤 **Exportación** — JSON, reportes y STIX 2.1.
- 👁 **Watchlist** — vigilancia periódica con alertas por Telegram (solo riesgo **técnico**).
- 🧱 **Hardening** — anti-SSRF, descarga acotada, logs atómicos, redacción de secretos.

---

## ⚖️ Principios éticos

1. **100% pasivo.** Sin escaneo activo de puertos (solo índice Shodan). Sin explotación.
2. **Sin juicios de bando.** El análisis narrativo es **simétrico** y cuenta marcadores en todas las direcciones. Un texto con muchos marcadores puede ser periodismo crítico legítimo.
3. **Sin geolocalización como señal de peligro.** La ubicación de un servidor no determina su riesgo.
4. **Separación de métricas.** `risk_score` = técnico. `narrative` = informativo. Nunca se mezclan.
5. **Sin claves en el código.** Solo `config.json` (chmod 600) o variables de entorno.

---

## 📦 Instalación

### Requisitos

- Python 3.9+
- pip

### Instalación

```bash
git clone https://github.com/Condor2026/circinuswatch.git
cd circinuswatch
pip install --break-system-packages -r requirements.txt
