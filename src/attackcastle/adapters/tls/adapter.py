from __future__ import annotations

import hashlib
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any

from attackcastle.adapters.command_runner import CommandSpec, run_command_spec
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import Evidence, NormalizedEntity, Observation, RunData, TLSAsset, new_id
from attackcastle.normalization.correlator import collect_tls_targets
from attackcastle.scan_policy import build_scan_policy

WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES", "MD5", "NULL", "EXPORT")
CERT_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
    re.DOTALL,
)


def _extract(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        return None
    return match.group(1).strip()


class TLSAdapter:
    name = "openssl"
    capability = "tls_probe"
    noise_score = 3
    cost_score = 3

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        previews: list[str] = []
        for item in collect_tls_targets(run_data)[:50]:
            host = str(item["host"])
            port = int(item["port"])
            previews.append(f"openssl s_client -connect {host}:{port} -servername {host}")
        return previews

    def _write_certificate_pem(self, artifact_dir: Path, host: str, port: int, stdout_text: str) -> Path | None:
        match = CERT_BLOCK_RE.search(stdout_text)
        if not match:
            return None
        pem_text = f"-----BEGIN CERTIFICATE-----{match.group(1)}-----END CERTIFICATE-----"
        pem_path = artifact_dir.parent / f"cert_{host.replace(':', '_')}_{port}.pem"
        pem_path.write_text(pem_text, encoding="utf-8")
        return pem_path

    def _parse_certificate(self, pem_path: Path) -> dict[str, Any]:
        completed = subprocess.run(  # noqa: S603
            [
                "openssl",
                "x509",
                "-in",
                str(pem_path),
                "-noout",
                "-subject",
                "-issuer",
                "-dates",
                "-ext",
                "subjectAltName",
                "-fingerprint",
                "-sha256",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        text = completed.stdout or ""
        sans: list[str] = []
        san_block = _extract(r"X509v3 Subject Alternative Name:\s*(?:\r?\n)?\s*(.+)", text)
        if san_block:
            for entry in san_block.split(","):
                normalized = entry.strip()
                if normalized.startswith("DNS:"):
                    sans.append(normalized[4:].strip())
        return {
            "subject": _extract(r"subject=([^\n]+)", text),
            "issuer": _extract(r"issuer=([^\n]+)", text),
            "not_before": _extract(r"notBefore=([^\n]+)", text),
            "not_after": _extract(r"notAfter=([^\n]+)", text),
            "sans": sans,
            "fingerprint_sha256": _extract(r"sha256 Fingerprint=([A-F0-9:]+)", text),
            "raw_text": text,
        }

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        result = AdapterResult()
        targets = collect_tls_targets(run_data)
        if not targets:
            return result

        policy = build_scan_policy(context.profile_name, context.config)
        timeout_seconds = int(context.config.get("scan", {}).get("tls_timeout_seconds", 10))
        max_targets = int(context.config.get("tls", {}).get("max_targets", 150))
        fingerprint_index: dict[str, list[str]] = defaultdict(list)

        for item in targets[:max_targets]:
            host = str(item["host"])
            port = int(item["port"])
            command_result = run_command_spec(
                context,
                CommandSpec(
                    tool_name=self.name,
                    capability=self.capability,
                    task_type="DetectTLSAndCertificates",
                    command=["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-showcerts"],
                    timeout_seconds=timeout_seconds,
                    artifact_prefix=f"openssl_{host.replace(':', '_')}_{port}",
                    stdin=subprocess.DEVNULL,
                ),
            )
            result.tool_executions.append(command_result.execution)
            result.evidence_artifacts.extend(command_result.evidence_artifacts)
            result.task_results.append(command_result.task_result)
            if command_result.task_result.status == "skipped":
                result.warnings.extend(command_result.task_result.warnings)
                return result

            protocol = _extract(r"Protocol\s*:\s*([^\n]+)", command_result.stdout_text)
            cipher = _extract(r"Cipher\s*:\s*([^\n]+)", command_result.stdout_text)
            artifact_dir = command_result.stdout_path
            pem_path = self._write_certificate_pem(artifact_dir, host, port, command_result.stdout_text)
            cert_details = {
                "subject": _extract(r"subject=([^\n]+)", command_result.stdout_text),
                "issuer": _extract(r"issuer=([^\n]+)", command_result.stdout_text),
                "not_before": None,
                "not_after": None,
                "sans": [],
                "fingerprint_sha256": None,
            }
            if pem_path is not None:
                result.evidence_artifacts.append(
                    command_result.evidence_artifacts[0].__class__(
                        artifact_id=new_id("artifact"),
                        kind="certificate",
                        path=str(pem_path),
                        source_tool=self.name,
                        caption=f"Certificate PEM for {host}:{port}",
                        source_task_id=command_result.task_result.task_id,
                        source_execution_id=command_result.execution_id,
                        hash_sha256=hashlib.sha256(pem_path.read_bytes()).hexdigest(),
                    )
                )
                cert_details = self._parse_certificate(pem_path)

            tls_entry = TLSAsset(
                tls_id=new_id("tls"),
                asset_id=str(item["asset_id"]),
                host=host,
                port=port,
                service_id=str(item.get("service_id") or "") or None,
                protocol=protocol,
                cipher=cipher,
                subject=cert_details.get("subject"),
                issuer=cert_details.get("issuer"),
                not_before=cert_details.get("not_before"),
                not_after=cert_details.get("not_after"),
                sans=list(cert_details.get("sans", [])),
                source_tool=self.name,
                source_execution_id=command_result.execution_id,
                parser_version="openssl_v1",
            )
            result.tls_assets.append(tls_entry)
            evidence = Evidence(
                evidence_id=new_id("evidence"),
                source_tool=self.name,
                kind="tls_handshake",
                snippet=f"{host}:{port} protocol={protocol} cipher={cipher}",
                artifact_path=str(command_result.stdout_path),
                selector={"kind": "line", "match": f"Protocol  : {protocol}"},
                source_execution_id=command_result.execution_id,
                parser_version="openssl_v1",
                confidence=0.95,
            )
            result.evidence.append(evidence)
            result.normalized_entities.append(
                NormalizedEntity(
                    entity_id=new_id("entity"),
                    entity_type="Certificate",
                    attributes={
                        "host": host,
                        "port": port,
                        "subject": cert_details.get("subject"),
                        "issuer": cert_details.get("issuer"),
                        "sans": list(cert_details.get("sans", [])),
                        "not_before": cert_details.get("not_before"),
                        "not_after": cert_details.get("not_after"),
                        "fingerprint_sha256": cert_details.get("fingerprint_sha256"),
                        "profile": policy.profile,
                    },
                    evidence_ids=[evidence.evidence_id],
                    source_tool=self.name,
                    source_task_id=command_result.task_result.task_id,
                    source_execution_id=command_result.execution_id,
                    parser_version="openssl_v1",
                )
            )
            result.observations.extend(
                [
                    Observation(
                        observation_id=new_id("obs"),
                        key="tls.protocol.version",
                        value=protocol,
                        entity_type="tls",
                        entity_id=tls_entry.tls_id,
                        source_tool=self.name,
                        confidence=0.95,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=command_result.execution_id,
                        parser_version="openssl_v1",
                    ),
                    Observation(
                        observation_id=new_id("obs"),
                        key="tls.subject_alt_names",
                        value=list(cert_details.get("sans", [])),
                        entity_type="tls",
                        entity_id=tls_entry.tls_id,
                        source_tool=self.name,
                        confidence=0.9,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=command_result.execution_id,
                        parser_version="openssl_v1",
                    ),
                ]
            )
            weak_cipher = any(token in str(cipher or "").upper() for token in WEAK_CIPHER_TOKENS)
            if protocol in WEAK_PROTOCOLS:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="tls.weak_protocol",
                        value=True,
                        entity_type="tls",
                        entity_id=tls_entry.tls_id,
                        source_tool=self.name,
                        confidence=0.92,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=command_result.execution_id,
                        parser_version="openssl_v1",
                    )
                )
            if weak_cipher:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="tls.weak_cipher",
                        value=True,
                        entity_type="tls",
                        entity_id=tls_entry.tls_id,
                        source_tool=self.name,
                        confidence=0.9,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=command_result.execution_id,
                        parser_version="openssl_v1",
                    )
                )
            fingerprint = str(cert_details.get("fingerprint_sha256") or "").replace(":", "").lower()
            if fingerprint:
                fingerprint_index[fingerprint].append(tls_entry.tls_id)
            command_result.task_result.parsed_entities = [
                {"type": "Certificate", "host": host, "port": port, "fingerprint_sha256": fingerprint}
            ]
            command_result.task_result.metrics = {"lines_parsed": len(command_result.stdout_text.splitlines()), "entities_created": 1, "entities_updated": 0}

        for fingerprint, tls_ids in fingerprint_index.items():
            if len(tls_ids) < 2:
                continue
            for tls_id in tls_ids:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="tls.cert.reused",
                        value={"fingerprint_sha256": fingerprint, "endpoint_count": len(tls_ids)},
                        entity_type="tls",
                        entity_id=tls_id,
                        source_tool=self.name,
                        confidence=0.8,
                        parser_version="openssl_v1",
                    )
                )

        result.facts["tls.scanned_endpoints"] = min(len(targets), max_targets)
        result.facts["tls_probe.scanned_endpoints"] = [f"{item['host']}:{item['port']}" for item in targets[:max_targets]]
        context.audit.write(
            "adapter.completed",
            {"adapter": self.name, "scanned_endpoints": min(len(targets), max_targets), "profile": policy.profile},
        )
        return result
