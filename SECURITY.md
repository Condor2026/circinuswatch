# Security Policy

## Versiones soportadas

| Versión | Soportada |
|---|---|
| 8.x | ✅ |
| 7.x | ❌ |

## Reportar una vulnerabilidad

Si encuentras una vulnerabilidad de seguridad en CircinusWatch:

1. **NO abras un issue público.**
2. Envía un correo a: `SpectrumSecIt@proton.me`
3. O usa [GitHub Security Advisories](https://github.com/Condor2026/Circinus_Watch/security/advisories/new).

Incluye:

- Descripción de la vulnerabilidad.
- Pasos para reproducirla.
- Impacto potencial.
- Versión afectada.
- Si tienes un fix propuesto, adjúntalo.

## Tiempo de respuesta

- **48 h** — acuse de recibo.
- **7 días** — evaluación inicial.
- **30 días** — fix o mitigación (si es viable).

## Alcance

Se consideran vulnerabilidades:

- Bypass del anti-SSRF.
- Inyección en logs o dashboard.
- Fuga de API keys en logs/errores.
- Corrupción de JSON por condiciones de carrera.
- Ejecución remota de código.
- XSS en el dashboard.

## Fuera de alcance

- DoS contra el propio usuario (descarga masiva controlada por `MAX_BODY_BYTES`).
- Falsos positivos del análisis narrativo.
- Resultados de APIs externas (VirusTotal, Shodan, etc.).
- Configuraciones inseguras del usuario (ej: `CIRCINUS_ALLOW_PRIVATE=1` en producción).

## Buenas prácticas

- Guarda `config.json` con permisos `600`.
- No subas `config.json` a ningún repo.
- Usa variables de entorno para producción.
- Mantén `requests`, `flask` y `rich` actualizados.
