from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from attackcastle.adapters.base import build_tool_execution
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import Evidence, Observation, RunData, new_id, now_utc

ADMIN_TOKENS = {
    "grafana": "Grafana panel",
    "kibana": "Kibana console",
    "jenkins": "Jenkins console",
    "rabbitmq": "RabbitMQ management",
    "portainer": "Portainer panel",
    "rancher": "Rancher console",
    "argocd": "Argo CD console",
    "prometheus": "Prometheus console",
    "sonarqube": "SonarQube console",
    "kubernetes dashboard": "Kubernetes dashboard",
    "phpmyadmin": "phpMyAdmin",
    "pgadmin": "pgAdmin",
    "mongo express": "Mongo Express",
    "redis commander": "Redis Commander",
    "teamcity": "TeamCity",
    "gitlab": "GitLab panel",
}
EDGE_TOKENS = {
    "elasticsearch": "search",
    "opensearch": "search",
    "solr": "search",
    "rabbitmq": "broker",
    "activemq": "broker",
    "kafka": "broker",
    "jenkins": "ci-cd",
    "teamcity": "ci-cd",
    "argocd": "ci-cd",
    "grafana": "observability",
    "prometheus": "observability",
    "kubernetes": "container",
    "portainer": "container",
    "rancher": "container",
}
API_DOC_TOKENS = {
    "swagger.json": "Swagger JSON",
    "openapi.json": "OpenAPI JSON",
    "api-docs": "API docs",
    "postman_collection.json": "Postman collection",
    "graphql": "GraphQL endpoint",
}
GITHUB_RE = re.compile(r"https?://(?:www\.)?github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", re.IGNORECASE)
PACKAGE_RE = re.compile(
    r"https?://(?:www\.)?(?:npmjs\.com/package|pypi\.org/project|hub\.docker\.com/r)/[A-Za-z0-9_.\-/]+",
    re.IGNORECASE,
)


def _obs_values(run_data: RunData, webapp_id: str, key: str) -> list[object]:
    return [
        observation.value
        for observation in run_data.observations
        if observation.entity_type == "web_app" and observation.entity_id == webapp_id and observation.key == key
    ]


def _read_artifact(path_value: str | None, max_chars: int = 6000) -> str:
    if not path_value:
        return ""
    path = Path(path_value)
    if not path.exists() or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")[:max_chars]


class SurfaceIntelAdapter:
    name = "surface_intel"
    capability = "surface_intelligence"
    noise_score = 2
    cost_score = 2

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        return [f"surface intelligence correlation ({len(run_data.web_apps)} web apps)"]

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        started_at = now_utc()
        result = AdapterResult()
        execution_id = new_id("exec")
        evidence_rows: list[dict[str, object]] = []
        technologies_by_webapp: dict[str, list[str]] = defaultdict(list)
        for technology in run_data.technologies:
            if technology.webapp_id:
                technologies_by_webapp[str(technology.webapp_id)].append(str(technology.name or ""))

        artifact_text_by_webapp: dict[str, str] = defaultdict(str)
        for evidence in run_data.evidence:
            if evidence.kind not in {"http_response", "web_discovery", "web_auxiliary_path", "web_fingerprint"}:
                continue
            snippet = evidence.snippet or ""
            content = _read_artifact(evidence.artifact_path)
            combined = f"{snippet}\n{content}".strip()
            if not combined:
                continue
            for web_app in run_data.web_apps:
                if web_app.url and web_app.url in combined:
                    artifact_text_by_webapp[web_app.webapp_id] += "\n" + combined

        for web_app in run_data.web_apps:
            title = str(web_app.title or "")
            url = str(web_app.url or "")
            discovered_urls = _obs_values(run_data, web_app.webapp_id, "web.discovery.urls")
            graphql_urls = _obs_values(run_data, web_app.webapp_id, "web.discovery.graphql_endpoints")
            source_maps = _obs_values(run_data, web_app.webapp_id, "web.discovery.source_maps")
            libraries = _obs_values(run_data, web_app.webapp_id, "web.discovery.libraries")
            combined_text = "\n".join(
                [
                    url,
                    title,
                    " ".join(technologies_by_webapp.get(web_app.webapp_id, [])),
                    json.dumps(discovered_urls),
                    json.dumps(graphql_urls),
                    json.dumps(source_maps),
                    json.dumps(libraries),
                    artifact_text_by_webapp.get(web_app.webapp_id, ""),
                ]
            ).lower()

            reasons: list[str] = []
            edge_categories: set[str] = set()
            api_exposures: list[str] = []
            github_refs = sorted(set(GITHUB_RE.findall(combined_text)))
            package_refs = sorted(set(PACKAGE_RE.findall(combined_text)))

            for token, label in ADMIN_TOKENS.items():
                if token in combined_text:
                    reasons.append(label)
            for token, category in EDGE_TOKENS.items():
                if token in combined_text:
                    edge_categories.add(category)
            for token, label in API_DOC_TOKENS.items():
                if token in combined_text:
                    api_exposures.append(label)
            if graphql_urls:
                api_exposures.append("GraphQL endpoint")
            if source_maps:
                api_exposures.append("Source maps exposed")

            if not (reasons or edge_categories or api_exposures or github_refs or package_refs):
                continue

            row = {
                "webapp_id": web_app.webapp_id,
                "url": url,
                "reasons": sorted(set(reasons)),
                "edge_categories": sorted(edge_categories),
                "api_exposures": sorted(set(api_exposures)),
                "github_refs": github_refs,
                "package_refs": package_refs,
            }
            evidence_rows.append(row)

            artifact_path = context.run_store.artifact_path(
                self.name, f"surface_{web_app.webapp_id}.json"
            )
            artifact_path.write_text(json.dumps(row, indent=2), encoding="utf-8")
            evidence = Evidence(
                evidence_id=new_id("evidence"),
                source_tool=self.name,
                kind="surface_intelligence",
                snippet=f"surface intelligence for {url}",
                artifact_path=str(artifact_path),
                selector={"kind": "json", "keys": ["reasons", "edge_categories", "api_exposures"]},
                source_execution_id=execution_id,
                parser_version="surface_intel_v1",
                confidence=0.84,
            )
            result.evidence.append(evidence)
            evidence_ids = [evidence.evidence_id]

            if reasons:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.admin_interface",
                        value=sorted(set(reasons)),
                        entity_type="web_app",
                        entity_id=web_app.webapp_id,
                        source_tool=self.name,
                        confidence=0.84,
                        evidence_ids=evidence_ids,
                        source_execution_id=execution_id,
                        parser_version="surface_intel_v1",
                    )
                )
            if edge_categories:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.edge.console.exposed",
                        value=sorted(edge_categories),
                        entity_type="web_app",
                        entity_id=web_app.webapp_id,
                        source_tool=self.name,
                        confidence=0.82,
                        evidence_ids=evidence_ids,
                        source_execution_id=execution_id,
                        parser_version="surface_intel_v1",
                    )
                )
            if api_exposures:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.api.docs.exposed",
                        value=sorted(set(api_exposures)),
                        entity_type="web_app",
                        entity_id=web_app.webapp_id,
                        source_tool=self.name,
                        confidence=0.86,
                        evidence_ids=evidence_ids,
                        source_execution_id=execution_id,
                        parser_version="surface_intel_v1",
                    )
                )
            if github_refs:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="thirdparty.github.reference",
                        value=github_refs,
                        entity_type="web_app",
                        entity_id=web_app.webapp_id,
                        source_tool=self.name,
                        confidence=0.8,
                        evidence_ids=evidence_ids,
                        source_execution_id=execution_id,
                        parser_version="surface_intel_v1",
                    )
                )
            if package_refs:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="thirdparty.package.reference",
                        value=package_refs,
                        entity_type="web_app",
                        entity_id=web_app.webapp_id,
                        source_tool=self.name,
                        confidence=0.8,
                        evidence_ids=evidence_ids,
                        source_execution_id=execution_id,
                        parser_version="surface_intel_v1",
                    )
                )

        summary_path = context.run_store.artifact_path(self.name, "surface_intelligence.json")
        summary_path.write_text(json.dumps(evidence_rows, indent=2), encoding="utf-8")
        result.facts["surface_intel.matches"] = len(evidence_rows)
        result.tool_executions.append(
            build_tool_execution(
                tool_name=self.name,
                command="internal surface intelligence correlation",
                started_at=started_at,
                ended_at=now_utc(),
                status="completed",
                execution_id=execution_id,
                capability=self.capability,
                exit_code=0,
                raw_artifact_paths=[str(summary_path)],
            )
        )
        context.audit.write(
            "adapter.completed",
            {"adapter": self.name, "matches": len(evidence_rows)},
        )
        return result
