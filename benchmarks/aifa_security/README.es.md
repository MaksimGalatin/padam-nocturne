# AIFaSecurity — Benchmark de Seguridad de Memoria para Agentes IA (100 Criterios, $0, sin LLM)

**AIFaSecurity** es un benchmark autónomo, determinista y gratuito (`$0`) con **100 experimentos medibles** (`AS-001`..`AS-100`) en 10 dominios para evaluar servidores MCP, sistemas de memoria, repositorios (`--target repo`) y URLs públicas (`--target url`).

```bash
python benchmarks/aifa_security/run_aifa_sec.py
padam aifa-sec --target url --path https://aifa.works --no-write
```
