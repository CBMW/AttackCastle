from __future__ import annotations

from attackcastle.adapters.web_discovery.parser import (
    detect_frontend_libraries,
    extract_discovery_urls,
    extract_framework_artifact_urls,
    extract_graphql_endpoints,
    extract_js_endpoints,
    extract_query_param_names,
    extract_script_urls,
    extract_source_map_urls,
    extract_structured_endpoints,
)


def test_extract_discovery_urls_same_host_only():
    html = """
    <a href="/admin">Admin</a>
    <a href="https://example.com/api?x=1">API</a>
    <a href="https://other.example.net/path">External</a>
    <form action="/submit"></form>
    """
    urls = extract_discovery_urls("https://example.com", html, same_host_only=True)
    assert "https://example.com/admin" in urls
    assert "https://example.com/api?x=1" in urls
    assert "https://other.example.net/path" not in urls


def test_extract_js_endpoints_and_query_params():
    body = """
    <script>
      fetch('/v1/users?id=5');
      axios.get("https://example.com/search?q=test");
    </script>
    """
    endpoints = extract_js_endpoints("https://example.com", body, same_host_only=True)
    assert "https://example.com/v1/users?id=5" in endpoints
    assert "https://example.com/search?q=test" in endpoints
    assert extract_query_param_names("https://example.com/search?q=test&sort=asc") == ["q", "sort"]


def test_extract_framework_artifacts_scripts_and_source_maps():
    html = """
    <script src="/static/app.js"></script>
    <script>
      fetch('/graphql');
      const spec = "/swagger-ui";
      //# sourceMappingURL=/static/app.js.map
    </script>
    <loc>https://example.com/api/openapi.json</loc>
    """
    assert "https://example.com/static/app.js" in extract_script_urls("https://example.com", html)
    assert "https://example.com/graphql" in extract_graphql_endpoints("https://example.com", html)
    assert "https://example.com/swagger-ui" in extract_framework_artifact_urls("https://example.com", html)
    assert "https://example.com/static/app.js.map" in extract_source_map_urls("https://example.com/static/app.js", html)
    assert "https://example.com/api/openapi.json" in extract_structured_endpoints("https://example.com", html)


def test_detect_frontend_libraries_from_bundle_text():
    bundle = """
    /*! jQuery v3.7.1 */
    axios/1.7.0
    react@18.2.0
    """
    libraries = detect_frontend_libraries(bundle)
    names = {item["name"] for item in libraries}
    assert "jQuery" in names
    assert "Axios" in names
    assert "React" in names
