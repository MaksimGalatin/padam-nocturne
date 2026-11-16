# Comparativa de Enmascarado de Secretos: PADAM vs Mem0 vs Claude-Mem

Comparativa abierta, offline (`$0`) y reproducible del enmascarado de secretos frente a claves sintéticas generadas y frases limpias.

## Qué se compara
1. **PADAM Nocturne** — `padam.safety.redact` (invocada por `Memory.remember` a través de `safety.clean`).
2. **Mem0** — 8 expresiones regulares de `mem0ai/mem0` (`integrations/codex-plugin/core/memory_core.py`, commit `f1791daa86d469249c9b002f62644d58a1eb96a0`).
3. **Claude-Mem** — 42 patrones integrados + 4 genéricos (`genericEnabled=False` y `True`) de `thedotmack/claude-mem` (`src/utils/redaction.ts`, commit `f705e9b99601dd9ac03e2f77c5aded6ff3d9471b`).

## Reproducir en un comando
```bash
python benchmarks/security/compare_masking.py
```
El resultado completo se guarda en `benchmarks/security/results_masking_1611.json`.

## Limitaciones
- Los patrones se portaron manualmente a Python `re` sin ejecutar código de terceros; los lookbehind de ancho variable de JS se convirtieron en grupos de captura `\1`.
- No se auditaron otros componentes fuera de los archivos citados; todas las claves del corpus son sintéticas.
