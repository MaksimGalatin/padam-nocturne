# -*- coding: utf-8 -*-
"""Подпись установщика PADAM Studio для автообновления Tauri (minisign: Ed25519 поверх BLAKE2b-512) и latest.json.
23.11.2026, слово Архитектора: «Версию Студии на ПК тоже обнови до последней… чтобы всегда подтягивалась новая версия».
Почему вручную: Tauri CLI на ПК нет, а в выпуск 0.7.2 подпись не попала (секрета ключа в GitHub нет) — без неё
встроенное в Studio автообновление не находит ни одной версии. Закрытый ключ читается из C:/Users/Admin/.tauri и
никуда не выводится; пароль — пустой, как в desktop/build_windows_installer.ps1.
    python -X utf8 desktop/sign_update_release.py <установщик.exe> <версия> <url установщика>
затем: gh release upload v<версия> latest.json <установщик.exe>.sig  (выпуск должен быть «последним» на GitHub).
Первое применение — 23.11.2026 для 0.7.2: подпись проверена открытым ключом, Studio 0.7.2 в журнале — update_up_to_date."""
import base64, hashlib, json, sys, time
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
sys.stdout.reconfigure(encoding="utf-8")
КЛЮЧ = Path(r"C:/Users/Admin/.tauri/padam-studio.key")
ОТКР = Path(r"C:/Users/Admin/.tauri/padam-studio.key.pub")


def минисайн_текст(b64_файл: str) -> bytes:
    текст = base64.b64decode(b64_файл).decode("utf-8")
    return base64.b64decode(текст.strip().split("\n")[1])


def параметры_scrypt(opslimit: int, memlimit: int):
    opslimit = max(opslimit, 32768); r = 8
    if opslimit < memlimit // 32:
        p = 1; maxN = opslimit // (r * 4)
        n = 1
        while n < 63 and (1 << n) <= maxN // 2: n += 1
    else:
        maxN = memlimit // (r * 128)
        n = 1
        while n < 63 and (1 << n) <= maxN // 2: n += 1
        maxrp = min((opslimit // 4) // (1 << n), 0x3FFFFFFF); p = maxrp // r
    return n, r, p


def закрытый(пароль: bytes = b""):
    b = минисайн_текст(КЛЮЧ.read_text(encoding="utf-8").strip())
    sig_alg, kdf_alg, cks_alg = b[0:2], b[2:4], b[4:6]
    salt = b[6:38]; ops = int.from_bytes(b[38:46], "little"); mem = int.from_bytes(b[46:54], "little")
    keynum = bytearray(b[54:158])
    if kdf_alg == b"Sc":
        n, r, p = параметры_scrypt(ops, mem)
        поток = hashlib.scrypt(пароль, salt=salt, n=1 << n, r=r, p=p, maxmem=2 ** 31 - 1, dklen=104)
        keynum = bytearray(x ^ y for x, y in zip(keynum, поток))
    key_id, sk, cks = bytes(keynum[0:8]), bytes(keynum[8:72]), bytes(keynum[72:104])
    if hashlib.blake2b(sig_alg + key_id + sk, digest_size=32).digest() != cks:
        raise SystemExit("контрольная сумма ключа не сошлась (неверный пароль?) — подпись не создана")
    return key_id, Ed25519PrivateKey.from_private_bytes(sk[:32])


def открытый():
    b = минисайн_текст(ОТКР.read_text(encoding="utf-8").strip())
    return b[2:10], Ed25519PublicKey.from_public_bytes(b[10:42])


def подписать(файл: Path) -> str:
    key_id, sk = закрытый()
    данные = файл.read_bytes()
    хэш = hashlib.blake2b(данные, digest_size=64).digest()
    sig = sk.sign(хэш)
    доверенный = f"timestamp:{int(time.time())}\tfile:{файл.name}"
    общий = sk.sign(sig + доверенный.encode("utf-8"))
    текст = ("untrusted comment: signature from tauri secret key\n" + base64.b64encode(b"ED" + key_id + sig).decode() + "\n"
             + "trusted comment: " + доверенный + "\n" + base64.b64encode(общий).decode() + "\n")
    return base64.b64encode(текст.encode("utf-8")).decode()


def проверить(файл: Path, sig_b64: str) -> bool:
    строки = base64.b64decode(sig_b64).decode("utf-8").strip().split("\n")
    box = base64.b64decode(строки[1]); доверенный = строки[2][len("trusted comment: "):]; общий = base64.b64decode(строки[3])
    key_id, pk = открытый()
    if box[0:2] != b"ED" or box[2:10] != key_id:
        return False
    pk.verify(box[10:74], hashlib.blake2b(файл.read_bytes(), digest_size=64).digest())
    pk.verify(общий, box[10:74] + доверенный.encode("utf-8"))
    return True


if __name__ == "__main__":
    exe, версия, url = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    sig = подписать(exe)
    print("подпись проверена открытым ключом из конфига Studio:", проверить(exe, sig))
    (exe.parent / (exe.name + ".sig")).write_text(sig, encoding="utf-8")
    latest = {"version": версия, "notes": f"PADAM Studio {версия}: https://github.com/MaksimGalatin/padam-nocturne/releases/tag/v{версия}",
              "pub_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "platforms": {"windows-x86_64": {"signature": sig, "url": url}}}
    (exe.parent / "latest.json").write_text(json.dumps(latest, ensure_ascii=False, indent=2), encoding="utf-8")
    print("готово:", exe.name + ".sig", "и latest.json")
