import json
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

from lsdf import Firewall, load_policy
from lsdf.demo_upstream import DemoUpstreamHandler
from lsdf.gateway import GatewayConfig, LSDFGatewayHandler


class DemoUpstreamTests(unittest.TestCase):
    def test_demo_upstream_non_streaming_shape(self):
        server = _start_server(DemoUpstreamHandler)
        try:
            request = urllib.request.Request(
                f"{_server_url(server)}/v1/chat/completions",
                data=json.dumps(
                    {"model": "demo", "messages": [{"role": "user", "content": "hello"}]}
                ).encode("utf-8"),
                headers={"content-type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = json.loads(response.read())
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(payload["object"], "chat.completion")
        self.assertIn("choices", payload)
        self.assertIn("LSDF-FIXTURE-00001", payload["choices"][0]["message"]["content"])

    def test_quickstart_gateway_path_redacts_demo_response_and_writes_audit(self):
        upstream_server = _start_server(DemoUpstreamHandler)
        audit_events = []

        class Handler(LSDFGatewayHandler):
            gateway_config = GatewayConfig(
                policy_path=None,
                policy_profile="default",
                upstream_base_url=_server_url(upstream_server),
                stream_holdback_chars=64,
            )
            gateway_firewall = Firewall(load_policy("policies/default.yaml"))
            gateway_audit_sink = _ListAuditSink(audit_events)

        gateway_server = _start_server(Handler)
        try:
            request = urllib.request.Request(
                f"{_server_url(gateway_server)}/v1/chat/completions",
                data=json.dumps(
                    {
                        "model": "demo",
                        "messages": [
                            {"role": "user", "content": "Show the normal content leak demo."}
                        ],
                    }
                ).encode("utf-8"),
                headers={"content-type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                body = response.read().decode("utf-8")
        finally:
            gateway_server.shutdown()
            gateway_server.server_close()
            upstream_server.shutdown()
            upstream_server.server_close()

        self.assertIn("<MRN:REDACTED>", body)
        self.assertNotIn("LSDF-FIXTURE-00001", body)
        self.assertEqual(
            [event["stage"] for event in audit_events],
            ["request_preflight", "response_inspection"],
        )
        self.assertNotIn("LSDF-FIXTURE-00001", json.dumps(audit_events))

    def test_quickstart_gateway_streaming_redacts_and_blocks_tool_call(self):
        upstream_server = _start_server(DemoUpstreamHandler)

        class Handler(LSDFGatewayHandler):
            gateway_config = GatewayConfig(
                policy_path=None,
                policy_profile="default",
                upstream_base_url=_server_url(upstream_server),
                stream_holdback_chars=64,
            )
            gateway_firewall = Firewall(load_policy("policies/default.yaml"))

        gateway_server = _start_server(Handler)
        try:
            stream_body = _post_gateway(
                gateway_server,
                {
                    "model": "demo",
                    "stream": True,
                    "messages": [{"role": "user", "content": "stream content"}],
                },
            )
            tool_body = _post_gateway(
                gateway_server,
                {
                    "model": "demo",
                    "stream": True,
                    "messages": [{"role": "user", "content": "stream tool call"}],
                },
            )
        finally:
            gateway_server.shutdown()
            gateway_server.server_close()
            upstream_server.shutdown()
            upstream_server.server_close()

        self.assertIn("<API_KEY:REDACTED>", stream_body)
        self.assertIn("[DONE]", stream_body)
        self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", stream_body)
        self.assertIn("sensitive_data_blocked", tool_body)
        self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", tool_body)


class _ListAuditSink:
    def __init__(self, events):
        self.events = events

    def write(self, event):
        self.events.append(event)


def _post_gateway(server, payload):
    request = urllib.request.Request(
        f"{_server_url(server)}/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.read().decode("utf-8")


def _start_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _server_url(server):
    host, port = server.server_address
    return f"http://{host}:{port}"


if __name__ == "__main__":
    unittest.main()
