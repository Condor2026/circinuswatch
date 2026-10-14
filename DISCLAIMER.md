# Disclaimer

**CircinusWatch** es una herramienta de **reconocimiento pasivo** y **auditoría de seguridad web**. Su objetivo es ayudar a investigadores, periodistas, equipos defensivos y curiosos a recopilar información pública.

## Qué NO es

- ❌ NO es una herramienta de ataque.
- ❌ NO realiza escaneo activo de puertos.
- ❌ NO explota vulnerabilidades.
- ❌ NO determina veracidad, intención ni "bando" de ningún contenido.
- ❌ NO sustituye análisis humano.
- ❌ NO es un veredicto sobre personas, medios o gobiernos.

## Sobre el análisis narrativo

El módulo de análisis narrativo detecta **MARCADORES LINGÜÍSTICOS** de encuadre beligerante/emocional. Es **simétrico**: cuenta marcadores en todas las direcciones (prorruso, proucraniano, pro-OTAN, anti-OTAN).

Un texto con muchos marcadores puede ser:

- Propaganda.
- Periodismo crítico legítimo.
- Discurso político vehemente.
- Cita de un tercero que se está criticando.
- Traducción automática con sesgo.

**Los resultados son heurísticos y requieren revisión humana.** No uses el análisis narrativo como única fuente para etiquetar un medio, persona o contenido.

## Separación de métricas

- `risk_score` — **técnico**. Basado en cabeceras, TLS, cookies, malware, threat intel.
- `narrative` — **informativo**. Basado en marcadores lingüísticos. **NO suma al riesgo técnico.**

## Uso responsable

No uses esta herramienta para:

- 🚫 Acosar, doxxear o etiquetar personas.
- 🚫 Vigilar a periodistas, activistas o medios.
- 🚫 Presentar heurísticas como veredictos.
- 🚫 Ninguna actividad ilegal en tu jurisdicción.
- 🚫 Automatizar campañas de desinformación o info-war.

## Jurisdicción

El uso de herramientas OSINT puede estar regulado en tu país. Es tu responsabilidad conocer y cumplir la legislación aplicable (protección de datos, secreto de comunicaciones, etc.).

## Sin garantía

El software se distribuye "tal cual", sin garantías. Los autores no se hacen responsables del uso indebido.

## Reportar vulnerabilidades

Ver [SECURITY.md](SECURITY.md).
