# ADR-0005: Forgetting = destroying a per-record key, with a receipt
- Status: accepted · Date: recorded 2026-11-19
## Context
Records copied to immutable storage cannot be deleted there; the owner still needs a real "forget".
## Decision
Each record is encrypted with its own key wrapped by the owner key. Forgetting destroys that key and issues a receipt;
the ciphertext anywhere becomes noise. `padam privacy-inventory` lists where personal data lives.
## Where in the code
`padam/keyvault.py` (per-record key `anchor_key.key_ref`, wrapped AES-256-GCM; destroyed key = `key_ref = 'destroyed'`), `forget_receipt` in `padam/memory.py`, `padam/privacy_inventory.py`.
