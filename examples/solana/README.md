# PADAM L3 + Solana Confidential Compute (`devnet` demo, `$0`)

Локальная проверка подписи якоря памяти и безопасный пример для `Solana devnet` без отправки транзакций, без ключей кошелька и без выхода в `mainnet`.

## Что проверяется бесплатно (`$0`, полностью офлайн)

1. Локальное зашифрованное формирование пакета L3 (`padam.anchor.build_bundle`) и вычисление дерева Меркла (`SHA-256(0x00 || record)` / `0x02 || forget` / `0x01 || left || right`).
2. Подписание якоря (`memo` + `root_hex` + `network="devnet"` + `measurement` + `slot`) ключом `Ed25519` (`padam.anchor.sign_anchor_attestation`).
3. Полная криптографическая проверка на стороне проверяющего (`padam.anchor.verify_anchor_attestation`):
   - пересчёт корня Меркла по сырому пакету и сверка с заметкой `Memo`;
   - проверка подписи `Ed25519` и отпечатка анклава (`measurement`);
   - блокировка `mainnet` при включённом `reject_mainnet=True`.

## Запуск

```bash
# Полностью офлайн (сеть не используется, $0):
python examples/solana/anchor_devnet_demo.py

# С опциональным read-only запросом текущего слота Solana devnet ($0):
python examples/solana/anchor_devnet_demo.py --rpc-slot
```

## Ограничения текущей беты Solana Confidential Compute

- Программа верификации TEE на Solana `devnet` находится в статусе экспериментальной беты (**без аудита безопасности**).
- Read-only проверка (`getSlot` / `verify_anchor_attestation`) полностью бесплатна (`$0`), тогда как запуск реального доверенного анклава AMD SEV-SNP требует выделенного облачного инстанса Confidential VM и в рамках данного примера не выполняется.
- Отправка реальных транзакций в `mainnet` **отключена и запрещена**.
