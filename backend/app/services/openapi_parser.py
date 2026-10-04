import json
import yaml
from typing import Dict, Any, List, Tuple
from app.models.api import AuthType


class OpenAPIParser:
    @staticmethod
    def parse_spec(spec_text: str) -> Dict[str, Any]:
        """Parses raw JSON or YAML text into a standard python dictionary."""
        spec_text = spec_text.strip()
        if not spec_text:
            raise ValueError("OpenAPI specification text is empty.")
        
        # Try JSON first
        if spec_text.startswith("{") or spec_text.startswith("["):
            try:
                return json.loads(spec_text)
            except json.JSONDecodeError:
                pass
        
        # Fallback to YAML
        try:
            return yaml.safe_load(spec_text)
        except Exception as e:
            raise ValueError(f"Failed to parse specification as JSON or YAML: {str(e)}")

    @classmethod
    def extract_inventory(cls, spec_data: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Extracts API metadata and all endpoint definitions from parsed OpenAPI 3.x / Swagger 2.0.
        Returns:
            (api_metadata, list_of_endpoints)
        """
        info = spec_data.get("info", {})
        title = info.get("title", "Imported API")
        description = info.get("description", "")
        version = info.get("version", "v1.0.0")

        # Determine base URL / servers
        base_url = "http://localhost:8000"
        servers = spec_data.get("servers", [])
        if servers and isinstance(servers, list) and len(servers) > 0:
            base_url = servers[0].get("url", base_url)
        elif "host" in spec_data:
            schemes = spec_data.get("schemes", ["https"])
            base_path = spec_data.get("basePath", "")
            base_url = f"{schemes[0]}://{spec_data['host']}{base_path}"

        api_meta = {
            "name": title,
            "description": description,
            "version": version,
            "base_url": base_url,
        }

        endpoints = []
        paths = spec_data.get("paths", {})
        
        # Determine global security schemes
        components = spec_data.get("components", {})
        security_schemes = components.get("securitySchemes", {}) or spec_data.get("securityDefinitions", {})

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Path-level parameters
            path_level_params = path_item.get("parameters", [])

            for method_str in ["get", "post", "put", "delete", "patch", "options", "head"]:
                if method_str not in path_item:
                    continue

                operation = path_item[method_str]
                if not isinstance(operation, dict):
                    continue

                summary = operation.get("summary") or operation.get("operationId") or f"{method_str.upper()} {path_str}"
                op_desc = operation.get("description", "")
                tags = operation.get("tags", [])
                deprecated = operation.get("deprecated", False)

                # Combine parameters
                op_params = operation.get("parameters", [])
                all_params = []
                for p in path_level_params + op_params:
                    if isinstance(p, dict):
                        all_params.append({
                            "name": p.get("name"),
                            "in": p.get("in"),
                            "required": p.get("required", False),
                            "description": p.get("description"),
                            "type": p.get("schema", {}).get("type") if "schema" in p else p.get("type", "string")
                        })

                # Request body schema (OpenAPI 3 vs Swagger 2)
                request_body_schema = {}
                if "requestBody" in operation:
                    req_content = operation["requestBody"].get("content", {})
                    if "application/json" in req_content:
                        request_body_schema = req_content["application/json"].get("schema", {})
                    elif req_content:
                        request_body_schema = list(req_content.values())[0].get("schema", {})

                # Responses
                responses_schema = operation.get("responses", {})

                # Security / Auth requirement
                security = operation.get("security", spec_data.get("security", []))
                is_authenticated = bool(security)
                auth_type = AuthType.NONE

                if is_authenticated and security_schemes:
                    # Detect auth type from security scheme
                    for sec_req in security:
                        for scheme_name in sec_req.keys():
                            scheme_def = security_schemes.get(scheme_name, {})
                            s_type = scheme_def.get("type", "").lower()
                            if s_type in ("http", "oauth2"):
                                if scheme_def.get("scheme", "").lower() == "bearer":
                                    auth_type = AuthType.BEARER_TOKEN
                                elif scheme_def.get("scheme", "").lower() == "basic":
                                    auth_type = AuthType.BASIC_AUTH
                                else:
                                    auth_type = AuthType.BEARER_TOKEN
                            elif s_type == "apikey":
                                auth_type = AuthType.API_KEY

                endpoint_record = {
                    "path": path_str,
                    "method": method_str.upper(),
                    "summary": summary,
                    "description": op_desc,
                    "parameters": all_params,
                    "request_body_schema": request_body_schema,
                    "responses_schema": responses_schema,
                    "is_authenticated": is_authenticated,
                    "auth_type": auth_type,
                    "is_deprecated": deprecated,
                    "tags": tags,
                }
                endpoints.append(endpoint_record)

        return api_meta, endpoints
