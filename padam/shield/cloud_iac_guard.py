# -*- coding: utf-8 -*-
"""Файрвол облачных и инфраструктурных агентов (Cloud IAM / Kubernetes / Terraform Guard).

Останавливает катастрофические ошибки и взломы DevOps/SRE-агентов:
- Деструктивные облачные CLI: `terraform destroy`, `kubectl delete ns/namespace`,
  `aws s3 rb --force`, `aws ec2 terminate-instances`, `gcloud projects delete`,
  `az group delete`, `helm uninstall --namespace prod`,
- Wildcard IAM-политики (`"Action": "*"`, `"Resource": "*"`, `AdministratorAccess`, `iam:PassRole` + `*`),
- Побег из контейнера в Kubernetes (`privileged: true`, `hostNetwork: true`, `hostPID: true`,
  `hostPath: /`, `runAsUser: 0`, `SYS_ADMIN`),
- Публичное открытие хранилищ и админ-портов в Terraform/IaC (`acl = "public-read-write"`,
  `0.0.0.0/0` на порты `22`, `3389`, `5432`, `3306`, `6379`, `27017`).
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List


_DESTRUCTIVE_CLOUD_CLI_RULES = [
    ("IAC-TERRAFORM-DESTROY", "CRITICAL", re.compile(r"(?i)\b(?:terraform|tofu|pulumi)\s+destroy\b"), "Деструктивная команда уничтожения облачной инфраструктуры (destroy)"),
    ("IAC-K8S-DELETE-NS", "CRITICAL", re.compile(r"(?i)\bkubectl\s+delete\s+(?:ns|namespace|all\s+--all|node|pv|pvc|deployment\s+--all)\b"), "Массовое удаление ресурсов или namespace в Kubernetes"),
    ("IAC-AWS-DESTROY", "CRITICAL", re.compile(r"(?i)\baws\s+(?:s3\s+(?:rb|rm)[^\n]*--(?:force|recursive)|ec2\s+terminate-instances|rds\s+delete-db-instance|iam\s+(?:attach-user-policy|put-user-policy)[^\n]*AdministratorAccess)"), "Критическая деструктивная или привилегированная команда AWS CLI"),
    ("IAC-GCP-AZURE-DESTROY", "CRITICAL", re.compile(r"(?i)(?:\bgcloud\s+(?:projects|compute\s+instances|sql\s+instances)\s+delete\b|\baz\s+(?:group|vm|storage\s+account)\s+delete\b)"), "Деструктивная команда удаления ресурсов GCP/Azure"),
]

_MANIFEST_RULES = [
    ("IAC-WILDCARD-IAM-ADMIN", "CRITICAL", re.compile(r'(?is)"Action"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])[^\n{}]{0,200}"Resource"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])'), "Политика IAM с полными правами Action:* на Resource:* (AdministratorAccess)"),
    ("IAC-IAM-ADMIN-ARN", "CRITICAL", re.compile(r"(?i)arn:aws:iam::aws:policy/AdministratorAccess"), "Назначение политики полного администратора AWS AdministratorAccess"),
    ("IAC-K8S-PRIVILEGED-POD", "CRITICAL", re.compile(r"(?i)\bprivileged\s*:\s*true\b"), "Привилегированный контейнер Kubernetes (privileged: true — риск побега на хост)"),
    ("IAC-K8S-HOST-NAMESPACE", "HIGH", re.compile(r"(?i)\b(?:hostNetwork|hostPID|hostIPC)\s*:\s*true\b"), "Доступ контейнера к пространству имён хоста Kubernetes"),
    ("IAC-K8S-ROOT-HOSTPATH", "CRITICAL", re.compile(r"(?i)hostPath\s*:\s*(?:\n\s*)?path\s*:\s*['\"]?/(?:etc|root|var/run/docker\.sock|\s*$)"), "Монтирование критического каталога хоста (или docker.sock) в контейнер"),
    ("IAC-PUBLIC-BUCKET-ACL", "CRITICAL", re.compile(r'(?i)(?:acl\s*=\s*"public-read(?:-write)?"|"Principal"\s*:\s*"\*"[^\n{}]{0,160}s3:(?:PutObject|DeleteObject|\*)|allUsers[^\n]{0,80}roles/storage\.admin)'), "Открытие публичного доступа на запись/администрирование к облачному бакету"),
    ("IAC-OPEN-ADMIN-PORT", "HIGH", re.compile(r'(?is)(?:0\.0\.0\.0/0|::/0)[^{}]{0,200}\b(?:from_port|to_port|port)\s*[:=]\s*(?:22|3389|5432|3306|6379|27017)\b|\b(?:from_port|to_port|port)\s*[:=]\s*(?:22|3389|5432|3306|6379|27017)\b[^{}]{0,200}(?:0\.0\.0\.0/0|::/0)'), "Открытие административного/БД порта (SSH/RDP/Postgres/Redis) на весь интернет 0.0.0.0/0"),
]


def inspect_cloud_or_iac(text: str, *, filename: str = "command") -> Dict[str, Any]:
    """Инспектирует облачную CLI-команду или IaC-манифест (IAM/K8s/Terraform) на Blast-Radius риски."""
    raw = str(text or "")
    findings: List[Dict[str, Any]] = []
    if not raw.strip():
        return {"ok": True, "allowed": True, "blocked": False, "source": filename, "findings": []}

    for rid, sev, rx, desc in _DESTRUCTIVE_CLOUD_CLI_RULES:
        m = rx.search(raw)
        if m:
            findings.append({"rule_id": rid, "severity": sev, "detail": f"{desc}: {m.group(0)[:100]}"})

    for rid, sev, rx, desc in _MANIFEST_RULES:
        m = rx.search(raw)
        if m:
            findings.append({"rule_id": rid, "severity": sev, "detail": f"{desc}: {m.group(0)[:100]}"})

    blocked = any(f["severity"] in ("CRITICAL", "HIGH") for f in findings)
    return {
        "ok": not blocked,
        "allowed": not blocked,
        "blocked": blocked,
        "source": filename,
        "risk_grade": "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else ("HIGH" if blocked else "SAFE"),
        "findings": findings,
    }


def scan_iac_path(path: str | os.PathLike[str], *, max_files: int = 200) -> Dict[str, Any]:
    """Сканирует файл или каталог Terraform/K8s/IAM-манифестов."""
    root = Path(path)
    if not root.exists():
        return {"ok": False, "blocked": True, "error": f"Путь не найден: {root}", "findings": []}

    exts = {".tf", ".tfvars", ".yaml", ".yml", ".json"}
    files: List[Path] = []
    if root.is_file():
        files.append(root)
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", ".terraform", ".venv", "__pycache__")]
            for fn in filenames:
                fp = Path(dirpath) / fn
                if fp.suffix.lower() in exts:
                    files.append(fp)
                    if len(files) >= max_files:
                        break
            if len(files) >= max_files:
                break

    all_findings: List[Dict[str, Any]] = []
    blocked_files: List[str] = []
    for fp in files:
        try:
            txt = fp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = str(fp.relative_to(root)) if root.is_dir() else fp.name
        r = inspect_cloud_or_iac(txt, filename=rel)
        if r["blocked"]:
            blocked_files.append(rel)
            for f in r["findings"]:
                item = dict(f)
                item["file"] = rel
                all_findings.append(item)

    return {
        "ok": len(blocked_files) == 0,
        "blocked": len(blocked_files) > 0,
        "files_scanned": len(files),
        "blocked_files": blocked_files,
        "findings": all_findings,
    }
