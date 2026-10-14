# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es/1.1.0/).
Versionado: [SemVer](https://semver.org/lang/es/).

## [8.0.0] - 2026-XX-XX

### Cambiado (ÉTICA)
- 🗣 **Análisis narrativo SIMÉTRICO**.
- 🌍 **Eliminado sesgo geográfico.**
- 📊 **Separación de métricas.**
- 🚨 **Telegram** solo alerta por riesgo técnico.
- 📝 Renombrado a "Passive OSINT & Web Security Audit".
- 🧹 Eliminados: `RUSSIAN_DOMAINS`, `_is_russian_domain`, TF-IDF/sklearn.

### Hardening
- [SEC-1] Anti-SSRF en cada redirección.
- [SEC-2] Descarga acotada.
- [SEC-3] Redacción de secretos.
- [SEC-4] Escritura atómica.
- [SEC-5] `config.json` 600.
- [SEC-6] Cabeceras case-insensitive.
- [SEC-7] Regex IOCs arreglada.
- [SEC-8] MITRE T1027.
- [SEC-9] `params=` en APIs.
- [SEC-10] `Text()` en Rich.
- [SEC-11] Dashboard con Host validation.
- [SEC-12] STIX 2.1 con UUIDv5.
- [SEC-13] Whitelist estricta.
- [SEC-14] Sufijos rusos corregidos.
- [SEC-15] `_guard()` por módulo.
- [SEC-16] TLS caducidad, versión débil, sin HTTPS.

### Añadido
- Exportación STIX 2.1.
- Watchlist con Telegram.
- Dashboard Flask con CSP.
