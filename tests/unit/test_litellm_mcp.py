from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from typing import Any

import httpx
import pytest

pytest.importorskip("litellm")

from litellm.exceptions import GuardrailRaisedException
from litellm.proxy._types import UserAPIKeyAuth
from litellm.types.guardrails import GuardrailEventHooks

from apparitor import LiteLLMMCPAuthorizationGuardrail
from apparitor.audit import AuditEvidence, AuditMetadata
from apparitor.config import ScannerConfig
from apparitor.errors import AuthZENConfigError


class EvidenceSink:
    def __init__(self) -> None:
        self.records: list[AuditEvidence] = []

    def record(self, record: AuditEvidence) -> None:
        self.records.append(record)


def _data(**overrides: Any) -> dict[str, Any]:
    return {
        "mcp_tool_name": "read_file",
        "mcp_arguments": {"path": "/public/example"},
        "mcp_server_name": "documents",
        **overrides,
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        {"event_hook": ["pre_call"]},
        {"event_hook": []},
        {"supported_event_hooks": ["during_mcp_call"]},
        {"default_on": False},
        {"run_in_parallel": True},
        {"scan_raw_request": True},
    ],
)
def test_mcp_hook_cannot_be_disabled_or_race_execution(kwargs) -> None:
    with pytest.raises(AuthZENConfigError):
        LiteLLMMCPAuthorizationGuardrail("https://pdp.example.com", **kwargs)


@pytest.mark.asyncio
async def test_mcp_adapter_selects_only_pre_execution_mcp_hook() -> None:
    guardrail = LiteLLMMCPAuthorizationGuardrail("https://pdp.example.com")
    try:
        for event in (
            GuardrailEventHooks.pre_call,
            GuardrailEventHooks.post_call,
            GuardrailEventHooks.during_mcp_call,
        ):
            assert not guardrail.should_run_guardrail({}, event)
        assert guardrail.should_run_guardrail({}, GuardrailEventHooks.pre_mcp_call)
    finally:
        await guardrail.aclose()


@pytest.mark.parametrize(
    "overrides",
    [
        {"mcp_tool_name": None},
        {"mcp_tool_name": " "},
        {"mcp_server_name": None},
        {"mcp_server_name": ""},
        {"mcp_server_name": "documents/private"},
        {"mcp_arguments": None},
        {"mcp_arguments": []},
        {"modified_arguments": "invalid"},
    ],
)
@pytest.mark.asyncio
async def test_malformed_mcp_context_refuses_without_pdp_call(overrides) -> None:
    requests = []
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: requests.append(request))
    ) as client:
        guardrail = LiteLLMMCPAuthorizationGuardrail("https://pdp.example.com", http_client=client)
        try:
            with pytest.raises(GuardrailRaisedException):
                await guardrail.async_pre_call_hook(
                    UserAPIKeyAuth(user_id="alice"), object(), _data(**overrides), "call_mcp_tool"
                )
            assert not requests
        finally:
            await guardrail.aclose()


@pytest.mark.asyncio
async def test_mcp_adapter_refuses_unknown_preliminary_shape_and_non_mcp_route() -> None:
    guardrail = LiteLLMMCPAuthorizationGuardrail("https://pdp.example.com")
    try:
        with pytest.raises(GuardrailRaisedException):
            await guardrail.async_pre_call_hook(
                UserAPIKeyAuth(user_id="alice"), object(), {}, "call_mcp_tool"
            )
        with pytest.raises(GuardrailRaisedException):
            await guardrail.async_pre_call_hook(
                UserAPIKeyAuth(user_id="alice"), object(), _data(), "completion"
            )
    finally:
        await guardrail.aclose()


@pytest.mark.asyncio
async def test_missing_auth_object_blocks_before_pdp() -> None:
    requests = []
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: requests.append(request))
    ) as client:
        guardrail = LiteLLMMCPAuthorizationGuardrail("https://pdp.example.com", http_client=client)
        try:
            with pytest.raises(GuardrailRaisedException):
                await guardrail.async_pre_call_hook(None, object(), _data(), "call_mcp_tool")
            assert not requests
        finally:
            await guardrail.aclose()


@pytest.mark.asyncio
async def test_unresolved_preliminary_request_refuses_without_authorizing() -> None:
    requests = []
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: requests.append(request))
    ) as client:
        guardrail = LiteLLMMCPAuthorizationGuardrail("https://pdp.example.com", http_client=client)
        data = {"name": "documents-read_file", "arguments": {"path": "/public/example"}}
        try:
            with pytest.raises(GuardrailRaisedException, match="MCP execution context"):
                await guardrail.async_pre_call_hook(
                    UserAPIKeyAuth(user_id="alice"), object(), data, "call_mcp_tool"
                )
            with pytest.raises(GuardrailRaisedException):
                await guardrail.async_pre_call_hook(
                    UserAPIKeyAuth(), object(), data, "call_mcp_tool"
                )
            assert not requests
        finally:
            await guardrail.aclose()


@pytest.mark.parametrize("route", ["virtual", "proxy", "rest", "forged_rest"])
@pytest.mark.asyncio
async def test_actual_virtual_pipeline_refuses_without_a_second_hook(monkeypatch, route) -> None:
    proxy_utils = pytest.importorskip("litellm.proxy.utils", exc_type=ImportError)
    import litellm
    from litellm.caching.dual_cache import DualCache
    from litellm.proxy import proxy_server
    from litellm.proxy._experimental.mcp_server import operations, rest_endpoints, tool_search
    from mcp.types import CallToolResult, TextContent
    from starlette.requests import Request

    requests = []
    executed = []
    sink = EvidenceSink()

    # This downstream handler deliberately executes without another guardrail dispatch.
    async def unchecked_executor(**kwargs):
        executed.append(kwargs)
        return CallToolResult(content=[TextContent(type="text", text="synthetic result")])

    monkeypatch.setattr(tool_search, "handle_mcp_tool_call", unchecked_executor)
    monkeypatch.setattr(tool_search, "handle_mcp_proxy_tool", unchecked_executor)
    monkeypatch.setattr(
        proxy_server, "proxy_logging_obj", proxy_utils.ProxyLogging(user_api_key_cache=DualCache())
    )
    monkeypatch.setattr(proxy_server, "general_settings", {})
    auth = UserAPIKeyAuth(
        user_id="alice",
        object_permission={"object_permission_id": "test", "mcp_tool_search_enabled": True},
    )
    name = (
        tool_search.MCP_PROXY_CALL_TOOL_NAME
        if route == "proxy"
        else tool_search.MCP_TOOL_CALL_TOOL_NAME
    )
    arguments = {"tool_name": "documents-read_file", "arguments": {"path": "/private"}}

    async def invoke():
        if route in ("rest", "forged_rest"):
            data = {"name": name, "arguments": arguments}
            if route == "forged_rest":
                data.update(_data())
            request = Request(
                {"type": "http", "method": "POST", "path": "/tools/call", "headers": []}
            )
            return await rest_endpoints._handle_virtual_mcp_tool(request, data, name, auth)
        return await operations._dispatch_virtual_mcp_tool(
            name=name,
            arguments=arguments,
            user_api_key_auth=auth,
            client_ip=None,
            mcp_proxy_mode=route == "proxy",
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: requests.append(request) or httpx.Response(200, json={"decision": True})
        )
    ) as client:
        guardrail = LiteLLMMCPAuthorizationGuardrail(
            "https://pdp.example.com",
            http_client=client,
            audit_sink=sink,
            audit_fingerprint_key=b"synthetic-test-key-at-least-32-bytes",
            audit_metadata_resolver=lambda auth: AuditMetadata("unresolved", "tenant-a"),
        )
        monkeypatch.setattr(litellm, "callbacks", [guardrail])
        try:
            with pytest.raises(GuardrailRaisedException, match="MCP execution context"):
                await invoke()
            assert not executed
            assert not requests
            assert sink.records[0].event_kind == "boundary_refusal"
            # Prove the real routing path reaches the deliberately unchecked executor
            # when this guardrail is absent, rather than failing at an unrelated SDK seam.
            monkeypatch.setattr(litellm, "callbacks", [])
            result = await invoke()
            assert result.content[0].text == "synthetic result"
            assert len(executed) == 1
        finally:
            await guardrail.aclose()


@pytest.mark.parametrize("modified", [{"path": "/private/example"}, {}, None])
@pytest.mark.asyncio
async def test_authorizes_effective_arguments_from_litellm_rewriters(modified) -> None:
    requests = []

    def pdp(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"decision": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(pdp)) as client:
        guardrail = LiteLLMMCPAuthorizationGuardrail(
            config=ScannerConfig(pdp_url="https://pdp.example.com", redact_arguments=False),
            http_client=client,
        )
        data = _data(modified_arguments=modified)
        try:
            assert (
                await guardrail.async_pre_call_hook(
                    UserAPIKeyAuth(user_id="alice"), object(), data, "call_mcp_tool"
                )
                is data
            )
            assert requests[0]["resource"]["properties"]["arguments"] == (
                modified or data["mcp_arguments"]
            )
        finally:
            await guardrail.aclose()


@pytest.mark.parametrize("case", ["allow", "deny", "pdp_error", "missing_identity", "review"])
@pytest.mark.parametrize("server_label", ["documents", "private-documents"])
@pytest.mark.asyncio
async def test_actual_litellm_manager_gates_transport_and_emits_evidence(
    monkeypatch, case, server_label
) -> None:
    proxy_utils = pytest.importorskip("litellm.proxy.utils", exc_type=ImportError)
    import litellm
    from litellm.caching.dual_cache import DualCache
    from litellm.proxy._experimental.mcp_server.mcp_server_manager import MCPServerManager
    from litellm.types.mcp import MCPTransport
    from litellm.types.mcp_server.mcp_server_manager import MCPServer
    from mcp.types import CallToolResult, TextContent

    requests = []
    executed = []
    sink = EvidenceSink()

    def pdp(request):
        body = json.loads(request.content)
        requests.append(body)
        return httpx.Response(
            503 if case == "pdp_error" else 200,
            json={
                "decision": case not in ("deny", "pdp_error"),
                "context": {"review": case == "review"},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(pdp)) as client:
        guardrail = LiteLLMMCPAuthorizationGuardrail(
            config=ScannerConfig(pdp_url="https://pdp.example.com", redact_arguments=False),
            http_client=client,
            default_on=True,
            review_predicate=lambda context: context.get("review", False),
            audit_sink=sink,
            audit_fingerprint_key=b"synthetic-test-key-at-least-32-bytes",
            audit_metadata_resolver=lambda auth: AuditMetadata(
                event_id="mcp-test", tenant_ref="tenant-a"
            ),
        )
        monkeypatch.setattr(litellm, "callbacks", [guardrail])
        dispatcher = proxy_utils.ProxyLogging(user_api_key_cache=DualCache())
        manager = MCPServerManager()
        server = MCPServer(
            server_id="synthetic-server",
            name=server_label,
            alias=server_label,
            transport=MCPTransport.http,
            url="https://mcp.example.test",
        )
        manager.registry[server.server_id] = server
        manager.tool_name_to_mcp_server_name_mapping = {
            "read_file": server_label,
        }

        async def transport(**kwargs):
            await asyncio.gather(*kwargs["tasks"])
            executed.append((kwargs["original_tool_name"], kwargs["arguments"]))
            return CallToolResult(content=[TextContent(type="text", text="synthetic result")])

        monkeypatch.setattr(manager, "_call_regular_mcp_tool", transport)
        auth = UserAPIKeyAuth(user_id=None if case == "missing_identity" else "alice")
        try:
            call = manager.call_tool(
                server_name=server_label,
                name="read_file",
                arguments={"path": "/public/example", "user_id": "attacker"},
                user_api_key_auth=auth,
                proxy_logging_obj=dispatcher,
                guardrail_context={"metadata": {"user_id": "attacker"}},
            )
            if case == "allow":
                result = await call
                assert result.content[0].text == "synthetic result"
                assert executed == [
                    ("read_file", {"path": "/public/example", "user_id": "attacker"})
                ]
            else:
                with pytest.raises(GuardrailRaisedException):
                    await call
                assert not executed
            if case == "missing_identity":
                assert not requests
            else:
                assert requests[0]["subject"] == {"type": "user", "id": "alice", "properties": {}}
                assert requests[0]["resource"]["type"] == "mcp_tool"
                assert requests[0]["resource"]["id"] == f"{server_label}/read_file"
                assert requests[0]["resource"]["properties"]["arguments"] == {
                    "path": "/public/example",
                    "user_id": "attacker",
                }
                assert sink.records
                assert sink.records[0].request_count == 1
                assert sink.records[0].tenant_ref == "tenant-a"
                assert sink.records[0].argument_fingerprints
                assert "/public/example" not in json.dumps(asdict(sink.records[0]))
        finally:
            await guardrail.aclose()
