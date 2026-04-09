from __future__ import annotations

import json
import re
import socket
from collections import Counter

from attackcastle.adapters.base import build_tool_execution, current_worker_budget, ordered_parallel_map
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import Evidence, Observation, ProofOutcome, ResponseDelta, RunData, ValidationResult, new_id, now_utc

SMTP_PORTS = {25, 465, 587}
DNS_PORTS = {53}
VPN_PORTS = {443, 4443, 500, 4500, 1194, 1701, 1723, 51820}
SSH_PORTS = {22}
FTP_PORTS = {20, 21}
RDP_PORTS = {3389}
SMB_PORTS = {139, 445}
REMOTE_ADMIN_PORTS = {22, 23, 3389, 5900}
VERSION_RE = re.compile(r"\b\d+(?:\.\d+){1,3}\b")


def _asset_lookup(run_data: RunData) -> dict[str, str]:
    return {asset.asset_id: asset.ip or asset.name for asset in run_data.assets if asset.ip or asset.name}


def _service_categories(port: int, name: str) -> list[str]:
    lowered = (name or "").lower()
    categories: list[str] = []
    if port in SMTP_PORTS or "smtp" in lowered:
        categories.append("smtp")
    if port in DNS_PORTS or lowered == "domain":
        categories.append("dns")
    if port in VPN_PORTS or any(token in lowered for token in ("vpn", "openvpn", "wireguard", "ipsec", "fortinet")):
        categories.append("vpn")
    if port in SSH_PORTS or "ssh" in lowered:
        categories.append("ssh")
    if port in FTP_PORTS or "ftp" in lowered:
        categories.append("ftp")
    if port in RDP_PORTS or "rdp" in lowered:
        categories.append("rdp")
    if port in SMB_PORTS or "microsoft-ds" in lowered or "netbios" in lowered or "smb" in lowered:
        categories.append("smb")
    return categories


def _recv_text(sock: socket.socket, max_bytes: int = 4096) -> str:
    chunks: list[bytes] = []
    while True:
        try:
            data = sock.recv(1024)
        except socket.timeout:
            break
        if not data:
            break
        chunks.append(data)
        if len(b"".join(chunks)) >= max_bytes or len(data) < 1024:
            break
    return b"".join(chunks).decode("utf-8", errors="ignore")


def _tcp_connect(host: str, port: int, timeout_seconds: int) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True, ""
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _probe_smtp(host: str, port: int, timeout_seconds: int, validate_open_relay: bool) -> dict[str, object]:
    outcome: dict[str, object] = {"banner": "", "starttls": False, "relay_possible": False}
    with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
        sock.settimeout(timeout_seconds)
        banner = _recv_text(sock)
        outcome["banner"] = banner.strip()
        sock.sendall(b"EHLO attackcastle.example\r\n")
        ehlo = _recv_text(sock)
        outcome["ehlo"] = ehlo.strip()
        outcome["starttls"] = "STARTTLS" in ehlo.upper()
        if validate_open_relay:
            sock.sendall(b"MAIL FROM:<relay-check@attackcastle.invalid>\r\n")
            mail_from = _recv_text(sock)
            sock.sendall(b"RCPT TO:<noreply@example.net>\r\n")
            rcpt_to = _recv_text(sock)
            sock.sendall(b"RSET\r\nQUIT\r\n")
            outcome["mail_from"] = mail_from.strip()
            outcome["rcpt_to"] = rcpt_to.strip()
            outcome["relay_possible"] = rcpt_to.lstrip().startswith(("250", "251"))
    return outcome


def _probe_ftp(host: str, port: int, timeout_seconds: int) -> dict[str, object]:
    outcome: dict[str, object] = {"banner": "", "auth_tls": False, "anonymous_login": False}
    with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
        sock.settimeout(timeout_seconds)
        outcome["banner"] = _recv_text(sock).strip()
        sock.sendall(b"FEAT\r\n")
        features = _recv_text(sock)
        outcome["features"] = features.strip()
        outcome["auth_tls"] = "AUTH TLS" in features.upper()
        sock.sendall(b"USER anonymous\r\n")
        user_response = _recv_text(sock)
        sock.sendall(b"PASS attackcastle@example.invalid\r\n")
        pass_response = _recv_text(sock)
        outcome["user_response"] = user_response.strip()
        outcome["pass_response"] = pass_response.strip()
        outcome["anonymous_login"] = pass_response.lstrip().startswith(("230", "202"))
        sock.sendall(b"QUIT\r\n")
    return outcome


def _probe_ssh(host: str, port: int, timeout_seconds: int) -> dict[str, object]:
    with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
        sock.settimeout(timeout_seconds)
        banner = _recv_text(sock)
    return {"banner": banner.strip()}


class ServiceExposureAdapter:
    name = "service_exposure"
    capability = "service_exposure_checks"
    noise_score = 3
    cost_score = 3

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        return [f"validate externally exposed services ({len(run_data.services)} services)"]

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        started_at = now_utc()
        result = AdapterResult()
        execution_id = new_id("exec")
        config = context.config.get("service_exposure", {})
        timeout_seconds = int(config.get("timeout_seconds", 5)) if isinstance(config, dict) else 5
        max_validations = int(config.get("max_validations", 120)) if isinstance(config, dict) else 120
        validate_open_relay = bool(config.get("enable_open_relay_probe", False)) if isinstance(config, dict) else False

        exposure_counter = Counter()
        evidence_rows: list[dict[str, object]] = []
        validation_counts = Counter()
        asset_lookup = _asset_lookup(run_data)
        validated = 0

        candidate_services = [
            service
            for service in run_data.services
            if _service_categories(int(service.port), service.name or "")
            or int(service.port) in REMOTE_ADMIN_PORTS
            or service.protocol.lower() == "udp"
        ]

        def _scan_service(item: tuple[int, Any]) -> dict[str, Any]:
            index, service = item
            partial = AdapterResult()
            host = asset_lookup.get(service.asset_id)
            categories = _service_categories(int(service.port), service.name or "")
            partial.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="service.open",
                    value=True,
                    entity_type="service",
                    entity_id=service.service_id,
                    source_tool=self.name,
                    confidence=0.9,
                    source_execution_id=execution_id,
                    parser_version="service_exposure_v2",
                )
            )
            partial.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="service.port",
                    value=int(service.port),
                    entity_type="service",
                    entity_id=service.service_id,
                    source_tool=self.name,
                    confidence=0.9,
                    source_execution_id=execution_id,
                    parser_version="service_exposure_v2",
                )
            )
            category_counts: Counter[str] = Counter()
            if service.protocol.lower() == "udp":
                partial.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="service.udp.detected",
                        value=True,
                        entity_type="service",
                        entity_id=service.service_id,
                        source_tool=self.name,
                        confidence=0.86,
                        source_execution_id=execution_id,
                        parser_version="service_exposure_v2",
                    )
                )
                category_counts["udp"] += 1
            for category in categories:
                category_counts[category] += 1
                partial.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key=f"service.{category}.exposed",
                        value=True,
                        entity_type="service",
                        entity_id=service.service_id,
                        source_tool=self.name,
                        confidence=0.84,
                        source_execution_id=execution_id,
                        parser_version="service_exposure_v2",
                    )
                )
                if category == "smtp":
                    partial.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="service.mail.detected",
                            value=True,
                            entity_type="service",
                            entity_id=service.service_id,
                            source_tool=self.name,
                            confidence=0.84,
                            source_execution_id=execution_id,
                            parser_version="service_exposure_v2",
                        )
                    )
            if int(service.port) in REMOTE_ADMIN_PORTS:
                category_counts["remote_admin"] += 1
                partial.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="service.remote_admin.exposed",
                        value=True,
                        entity_type="service",
                        entity_id=service.service_id,
                        source_tool=self.name,
                        confidence=0.84,
                        source_execution_id=execution_id,
                        parser_version="service_exposure_v2",
                    )
                )
            validation: dict[str, object] = {
                "service_id": service.service_id,
                "asset_id": service.asset_id,
                "host": host,
                "port": int(service.port),
                "name": service.name or "",
                "protocol": service.protocol,
                "categories": categories,
                "banner": service.banner or "",
                "validated": False,
            }
            validated_count = 0
            if host and service.protocol.lower() == "tcp" and index < max_validations:
                validated_count = 1
                probe_outcome: dict[str, object] = {}
                connect_ok, connect_error = _tcp_connect(host, int(service.port), timeout_seconds)
                validation["connect_ok"] = connect_ok
                if connect_error:
                    validation["connect_error"] = connect_error
                if connect_ok and "smtp" in categories:
                    probe_outcome = _probe_smtp(host, int(service.port), timeout_seconds, validate_open_relay)
                elif connect_ok and "ftp" in categories:
                    probe_outcome = _probe_ftp(host, int(service.port), timeout_seconds)
                elif connect_ok and "ssh" in categories:
                    probe_outcome = _probe_ssh(host, int(service.port), timeout_seconds)
                validation.update(probe_outcome)
                validation["validated"] = connect_ok
                artifact_path = context.run_store.artifact_path(self.name, f"service_{service.service_id}_{service.port}.json")
                artifact_path.write_text(json.dumps(validation, indent=2), encoding="utf-8")
                evidence = Evidence(
                    evidence_id=new_id("evidence"),
                    source_tool=self.name,
                    kind="service_validation",
                    snippet=f"{host}:{service.port} validation categories={categories}",
                    artifact_path=str(artifact_path),
                    selector={"kind": "json", "keys": ["host", "port", "banner", "categories"]},
                    source_execution_id=execution_id,
                    parser_version="service_exposure_v2",
                    confidence=0.88 if connect_ok else 0.72,
                )
                partial.evidence.append(evidence)
                evidence_ids = [evidence.evidence_id]
                partial.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="service.validation.performed",
                        value=connect_ok,
                        entity_type="service",
                        entity_id=service.service_id,
                        source_tool=self.name,
                        confidence=0.88,
                        evidence_ids=evidence_ids,
                        source_execution_id=execution_id,
                        parser_version="service_exposure_v2",
                    )
                )
                if VERSION_RE.search(str(validation.get("banner") or service.banner or "")):
                    partial.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="service.version.disclosed",
                            value=True,
                            entity_type="service",
                            entity_id=service.service_id,
                            source_tool=self.name,
                            confidence=0.83,
                            evidence_ids=evidence_ids,
                            source_execution_id=execution_id,
                            parser_version="service_exposure_v2",
                        )
                    )
                    partial.validation_results.append(
                        ValidationResult(
                            validation_result_id=new_id("vresult"),
                            replay_request_id="",
                            webapp_id="",
                            validator_key="service_version_disclosure",
                            family="component",
                            category="version_exposure",
                            status="candidate",
                            title="Service version disclosure observed",
                            summary="Banner or probe output exposed version material suitable for CVE enrichment.",
                            entity_type="service",
                            entity_id=service.service_id,
                            service_id=service.service_id,
                            protocol_family=categories[0] if categories else service.name or service.protocol,
                            severity_hint="medium",
                            confidence=0.83,
                            coverage_lane_id=f"service:{service.service_id}:service_version_and_cve_enrichment",
                            attack_path_id=f"service:{service.service_id}:service_version_and_cve_enrichment",
                            playbook_key="service_version_and_cve_enrichment",
                            step_key="service_version_correlation",
                            stop_reason="version material disclosed without authenticated interaction",
                            proof_strength="medium",
                            evidence_ids=evidence_ids,
                            tags=["service", "version", "candidate"],
                            details={"host": host, "port": int(service.port), "banner": validation.get("banner") or service.banner or ""},
                            source_tool=self.name,
                            source_execution_id=execution_id,
                            parser_version="service_exposure_v3",
                        )
                    )
                    validation_counts["candidate"] += 1
                if validation.get("starttls") is True:
                    partial.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="mail.starttls.supported",
                            value=True,
                            entity_type="service",
                            entity_id=service.service_id,
                            source_tool=self.name,
                            confidence=0.9,
                            evidence_ids=evidence_ids,
                            source_execution_id=execution_id,
                            parser_version="service_exposure_v2",
                        )
                    )
                if "smtp" in categories and validation.get("validated") is True and validation.get("starttls") is False:
                    partial.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="mail.starttls.supported",
                            value=False,
                            entity_type="service",
                            entity_id=service.service_id,
                            source_tool=self.name,
                            confidence=0.82,
                            evidence_ids=evidence_ids,
                            source_execution_id=execution_id,
                            parser_version="service_exposure_v2",
                        )
                    )
                if validation.get("relay_possible") is True:
                    partial.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="mail.open_relay.possible",
                            value=True,
                            entity_type="service",
                            entity_id=service.service_id,
                            source_tool=self.name,
                            confidence=0.92,
                            evidence_ids=evidence_ids,
                            source_execution_id=execution_id,
                            parser_version="service_exposure_v2",
                        )
                    )
                    partial.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="smtp.open_relay.confirmed",
                            value=True,
                            entity_type="service",
                            entity_id=service.service_id,
                            source_tool=self.name,
                            confidence=0.94,
                            evidence_ids=evidence_ids,
                            source_execution_id=execution_id,
                            parser_version="service_exposure_v3",
                        )
                    )
                    partial.response_deltas.append(
                        ResponseDelta(
                            response_delta_id=new_id("delta"),
                            replay_request_id="",
                            attack_path_id=f"service:{service.service_id}:smtp_exposure",
                            step_key="smtp_relay_check",
                            protocol_family="smtp",
                            interaction_target=f"{host}:{service.port}",
                            comparison_type="protocol_probe",
                            summary="SMTP relay check accepted an external recipient without authentication.",
                            evidence_ids=evidence_ids,
                            details={"mail_from": validation.get("mail_from"), "rcpt_to": validation.get("rcpt_to")},
                            source_tool=self.name,
                            source_execution_id=execution_id,
                            parser_version="service_exposure_v3",
                        )
                    )
                    confirmed_result = ValidationResult(
                        validation_result_id=new_id("vresult"),
                        replay_request_id="",
                        webapp_id="",
                        validator_key="smtp_open_relay",
                        family="infra",
                        category="service_exposure",
                        status="confirmed",
                        title="SMTP open relay confirmed",
                        summary="The SMTP service accepted unauthenticated relay behavior during protocol probing.",
                        entity_type="service",
                        entity_id=service.service_id,
                        service_id=service.service_id,
                        protocol_family="smtp",
                        severity_hint="high",
                        confidence=0.94,
                        coverage_lane_id=f"service:{service.service_id}:smtp_exposure",
                        attack_path_id=f"service:{service.service_id}:smtp_exposure",
                        playbook_key="smtp_exposure",
                        step_key="smtp_relay_check",
                        response_delta={"summary": "RCPT TO accepted external recipient", "relay_possible": True},
                        stop_reason="explicit unauthenticated relay acceptance observed",
                        proof_strength="strong",
                        evidence_ids=evidence_ids,
                        tags=["smtp", "relay", "confirmed"],
                        details={"host": host, "port": int(service.port), "validated": True},
                        source_tool=self.name,
                        source_execution_id=execution_id,
                        parser_version="service_exposure_v3",
                    )
                    partial.validation_results.append(confirmed_result)
                    partial.proof_outcomes.append(
                        ProofOutcome(
                            proof_outcome_id=new_id("proof"),
                            attack_path_id=confirmed_result.attack_path_id or "",
                            playbook_key="smtp_exposure",
                            step_key="smtp_relay_check",
                            status="confirmed",
                            reason="The SMTP service relayed an external recipient without credentials.",
                            strength="strong",
                            validation_result_id=confirmed_result.validation_result_id,
                            evidence_ids=evidence_ids,
                            details={"host": host, "port": int(service.port)},
                            source_tool=self.name,
                            source_execution_id=execution_id,
                            parser_version="service_exposure_v3",
                        )
                    )
                    validation_counts["confirmed"] += 1
                if validation.get("auth_tls") is True:
                    partial.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="ftp.auth_tls.supported",
                            value=True,
                            entity_type="service",
                            entity_id=service.service_id,
                            source_tool=self.name,
                            confidence=0.88,
                            evidence_ids=evidence_ids,
                            source_execution_id=execution_id,
                            parser_version="service_exposure_v2",
                        )
                    )
                if validation.get("anonymous_login") is True:
                    partial.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="ftp.anonymous.enabled",
                            value=True,
                            entity_type="service",
                            entity_id=service.service_id,
                            source_tool=self.name,
                            confidence=0.94,
                            evidence_ids=evidence_ids,
                            source_execution_id=execution_id,
                            parser_version="service_exposure_v3",
                        )
                    )
                    partial.response_deltas.append(
                        ResponseDelta(
                            response_delta_id=new_id("delta"),
                            replay_request_id="",
                            attack_path_id=f"service:{service.service_id}:ftp_exposure",
                            step_key="ftp_anonymous_check",
                            protocol_family="ftp",
                            interaction_target=f"{host}:{service.port}",
                            comparison_type="protocol_probe",
                            summary="FTP anonymous login succeeded without credentials.",
                            evidence_ids=evidence_ids,
                            details={"user_response": validation.get("user_response"), "pass_response": validation.get("pass_response")},
                            source_tool=self.name,
                            source_execution_id=execution_id,
                            parser_version="service_exposure_v3",
                        )
                    )
                    confirmed_result = ValidationResult(
                        validation_result_id=new_id("vresult"),
                        replay_request_id="",
                        webapp_id="",
                        validator_key="ftp_anonymous_access",
                        family="infra",
                        category="service_exposure",
                        status="confirmed",
                        title="FTP anonymous access confirmed",
                        summary="The FTP service accepted unauthenticated anonymous login.",
                        entity_type="service",
                        entity_id=service.service_id,
                        service_id=service.service_id,
                        protocol_family="ftp",
                        severity_hint="high",
                        confidence=0.94,
                        coverage_lane_id=f"service:{service.service_id}:ftp_exposure",
                        attack_path_id=f"service:{service.service_id}:ftp_exposure",
                        playbook_key="ftp_exposure",
                        step_key="ftp_anonymous_check",
                        response_delta={"summary": "230/202 FTP anonymous login response observed", "anonymous_login": True},
                        stop_reason="explicit anonymous login acceptance observed",
                        proof_strength="strong",
                        evidence_ids=evidence_ids,
                        tags=["ftp", "anonymous", "confirmed"],
                        details={"host": host, "port": int(service.port), "validated": True},
                        source_tool=self.name,
                        source_execution_id=execution_id,
                        parser_version="service_exposure_v3",
                    )
                    partial.validation_results.append(confirmed_result)
                    partial.proof_outcomes.append(
                        ProofOutcome(
                            proof_outcome_id=new_id("proof"),
                            attack_path_id=confirmed_result.attack_path_id or "",
                            playbook_key="ftp_exposure",
                            step_key="ftp_anonymous_check",
                            status="confirmed",
                            reason="The FTP service accepted anonymous login without credentials.",
                            strength="strong",
                            validation_result_id=confirmed_result.validation_result_id,
                            evidence_ids=evidence_ids,
                            details={"host": host, "port": int(service.port)},
                            source_tool=self.name,
                            source_execution_id=execution_id,
                            parser_version="service_exposure_v3",
                        )
                    )
                    validation_counts["confirmed"] += 1
                elif connect_ok and (
                    any(category in {"rdp", "smb", "vpn"} for category in categories)
                    or int(service.port) in REMOTE_ADMIN_PORTS
                ):
                    category = next((item for item in categories if item in {"rdp", "smb", "vpn", "ssh"}), "remote_admin")
                    candidate_result = ValidationResult(
                        validation_result_id=new_id("vresult"),
                        replay_request_id="",
                        webapp_id="",
                        validator_key=f"{category}_exposed_surface",
                        family="infra",
                        category="service_exposure",
                        status="candidate",
                        title=f"{category.upper()} exposure requires analyst follow-up",
                        summary="The service is externally reachable without credentials, but deeper verification remains manual in unauthenticated-only mode.",
                        entity_type="service",
                        entity_id=service.service_id,
                        service_id=service.service_id,
                        protocol_family=category,
                        severity_hint="medium" if category == "ssh" else "high",
                        confidence=0.8,
                        coverage_lane_id=f"service:{service.service_id}:{category if category != 'remote_admin' else 'generic_remote_admin_exposure'}",
                        attack_path_id=f"service:{service.service_id}:{category if category != 'remote_admin' else 'generic_remote_admin_exposure'}",
                        playbook_key=(
                            f"{category}_exposure"
                            if category in {"ssh", "ftp", "smtp", "rdp", "smb"}
                            else ("vpn_remote_access_exposure" if category == "vpn" else "generic_remote_admin_exposure")
                        ),
                        step_key=f"{category}_boundary_review",
                        stop_reason="unauthenticated-only mode preserves this as coverage plus manual follow-up",
                        proof_strength="medium",
                        evidence_ids=evidence_ids,
                        tags=[category, "candidate", "manual-followup"],
                        details={"host": host, "port": int(service.port), "connect_ok": connect_ok},
                        source_tool=self.name,
                        source_execution_id=execution_id,
                        parser_version="service_exposure_v3",
                    )
                    partial.validation_results.append(candidate_result)
                    validation_counts["candidate"] += 1
            return {"partial": partial, "validation": validation, "counts": category_counts, "validated": validated_count}

        remaining_services = list(enumerate(candidate_services))
        while remaining_services:
            worker_count = current_worker_budget(
                context,
                self.capability,
                stage="enumeration",
                pending_count=len(remaining_services),
                ceiling=len(remaining_services),
                fallback=1,
            )
            batch = remaining_services[:worker_count]
            remaining_services = remaining_services[worker_count:]
            for item in ordered_parallel_map(batch, max_workers=worker_count, worker=_scan_service):
                partial = item["partial"]
                exposure_counter.update(item["counts"])
                validated += int(item["validated"])
                evidence_rows.append(item["validation"])
                result.evidence.extend(partial.evidence)
                result.observations.extend(partial.observations)
                result.response_deltas.extend(partial.response_deltas)
                result.validation_results.extend(partial.validation_results)
                result.proof_outcomes.extend(partial.proof_outcomes)

        artifact_path = context.run_store.artifact_path(self.name, "service_exposure.json")
        artifact_path.write_text(
            json.dumps({"summary": dict(exposure_counter), "services": evidence_rows}, indent=2),
            encoding="utf-8",
        )
        evidence = Evidence(
            evidence_id=new_id("evidence"),
            source_tool=self.name,
            kind="service_exposure",
            snippet=f"service exposure categories: {dict(exposure_counter)}",
            artifact_path=str(artifact_path),
            selector={"kind": "json", "items": len(evidence_rows)},
            source_execution_id=execution_id,
            parser_version="service_exposure_v2",
            confidence=0.8,
        )
        result.evidence.append(evidence)
        for observation in result.observations:
            if not observation.evidence_ids:
                observation.evidence_ids = [evidence.evidence_id]

        ended_at = now_utc()
        result.facts["service_exposure.counts"] = dict(exposure_counter)
        result.facts["service_exposure.service_count"] = len(evidence_rows)
        result.facts["service_exposure.validated_count"] = validated
        result.facts["service_exposure.validation_counts"] = dict(validation_counts)
        result.facts["coverage_engine.service_validation_counts"] = dict(validation_counts)
        result.tool_executions.append(
            build_tool_execution(
                tool_name=self.name,
                command="external service validation",
                started_at=started_at,
                ended_at=ended_at,
                status="completed",
                execution_id=execution_id,
                capability=self.capability,
                exit_code=0,
                raw_artifact_paths=[str(artifact_path)],
            )
        )
        context.audit.write(
            "adapter.completed",
            {
                "adapter": self.name,
                "services_analyzed": len(run_data.services),
                "validated": validated,
                "exposed_services": len(evidence_rows),
            },
        )
        return result
