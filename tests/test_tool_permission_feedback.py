# SPDX-License-Identifier: Apache-2.0
import json
import re
import string
import unittest
from copy import deepcopy

from lsdf import Firewall, load_policy
from lsdf.eval_matrix import ENTITY_SAMPLES
from lsdf.gateway import handle_chat_completion, handle_streaming_chat_completion
from lsdf.scanners.entropy import EntropySecretScanner
from lsdf.scanners.regex import PatternRecognizer, RegexScanner
from lsdf.streaming import format_sse_event
from lsdf.surfaces import Surface


PREFIX = (
    "The user has specified a rule which prevents you from using this specific tool call. "
    "Here are some of the relevant rules "
)
CACHE_GLOB = "/tmp/client-data/opencode/tool-output/*"
RULES = [
    {"permission": "*", "action": "allow", "pattern": "*"},
    {"permission": "external_directory", "pattern": "*", "action": "ask"},
    {"permission": "external_directory", "pattern": CACHE_GLOB, "action": "allow"},
    {"permission": "external_directory", "pattern": "/tmp/opencode/*", "action": "allow"},
    {"permission": "*", "action": "deny", "pattern": "*"},
    {"permission": "external_directory", "pattern": CACHE_GLOB, "action": "allow"},
]


def refusal(rules=None, **kwargs):
    return PREFIX + json.dumps(RULES if rules is None else rules, **kwargs)


def payload(text):
    return {"messages": [{"role": "tool", "tool_call_id": "call_example", "content": text}]}


class ToolPermissionFeedbackTests(unittest.TestCase):
    def setUp(self):
        self.firewall = Firewall(load_policy("policies/default.yaml"))
        self.entropy = EntropySecretScanner()

    def scan(self, text, surface="input.tool_results"):
        return self.entropy.scan(Surface(name=surface, pointer=("content",), value=text))

    def test_exact_refusal_and_formatted_rules_preserve_payload(self):
        compact = refusal(separators=(",", ":"))
        self.assertEqual(len(compact), 577)
        baseline = self.scan(compact, "input.messages")
        self.assertEqual(
            [(finding.start, finding.end) for finding in baseline],
            [(187, 205), (252, 270), (283, 322), (357, 375), (487, 505), (518, 557)],
        )
        self.assertEqual([finding.value for finding in baseline], ["external_directory", "external_directory", CACHE_GLOB, "external_directory", "external_directory", CACHE_GLOB])
        for text in (compact, refusal(indent=2), refusal(list(reversed(RULES)))):
            with self.subTest(format_length=len(text)):
                self.assertFalse(self.scan(text))
                result = self.firewall.inspect(payload(text))
                self.assertFalse(result.blocked)
                self.assertEqual(result.transformed_payload, payload(text))

    def test_permission_feedback_forwards_unchanged_json_and_sse(self):
        request = payload(refusal())
        response = {"object": "chat.completion", "choices": [{"message": {"role": "assistant", "content": "Retry inside the workspace."}}]}
        for stream in (False, True):
            with self.subTest(stream=stream):
                forwarded = []
                def forward(actual):
                    forwarded.append(actual)
                    if stream:
                        chunk = {"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": "Retry inside the workspace."}}]}
                        return 200, {"content-type": "text/event-stream"}, [format_sse_event(chunk), b"data: [DONE]\n\n"]
                    return 200, {"content-type": "application/json"}, json.dumps(response).encode()
                handler = handle_streaming_chat_completion if stream else handle_chat_completion
                status, _headers, body, _extra = handler(request, self.firewall, forward)
                content = b"".join(body) if stream else body
                self.assertEqual(status, 200)
                self.assertEqual(forwarded, [request])
                self.assertIn(b"Retry inside the workspace.", content)
                if stream:
                    self.assertIn(b"[DONE]", content)

    def test_secrets_in_rule_fields_and_prose_block_before_forward(self):
        secret = ENTITY_SAMPLES["API_KEY"][0]
        variants = []
        for field in ("permission", "pattern", "action", "extra"):
            rules = deepcopy(RULES)
            rules[2][field] = secret
            variants.append(refusal(rules))
        variants.append(refusal() + " " + secret)
        variants.append(refusal().replace("/tmp/client-data", "/tmp/" + secret))
        for index, text in enumerate(variants):
            for stream in (False, True):
                with self.subTest(case=index, stream=stream):
                    called = []
                    handler = handle_streaming_chat_completion if stream else handle_chat_completion
                    status, _headers, body, _extra = handler(payload(text), self.firewall, lambda actual: called.append(actual))
                    content = b"".join(body) if stream else body
                    self.assertEqual(status, 403)
                    self.assertFalse(called)
                    self.assertNotIn(secret.encode(), content)
                    result = self.firewall.inspect(payload(text))
                    self.assertTrue(result.blocked)
                    self.assertNotIn(secret, json.dumps(result.audit_event))

    def test_other_surfaces_and_missing_refusal_context_get_no_exception(self):
        text = refusal()
        for surface in ("input.messages", "input.system", "output.content", "output.tool_calls.arguments", "logs.traces"):
            with self.subTest(surface=surface):
                self.assertTrue(self.scan(text, surface))
        for text in ("external_directory", CACHE_GLOB, json.dumps(RULES), "Unrecognized error: " + json.dumps(RULES)):
            with self.subTest(context_length=len(text)):
                self.assertTrue(self.scan(text))

    def test_malformed_nested_duplicate_unknown_and_oversized_rules_get_no_exception(self):
        unknown = deepcopy(RULES)
        unknown[0]["extra"] = "safe"
        wrong_type = deepcopy(RULES)
        wrong_type[0]["pattern"] = None
        wrong_action = deepcopy(RULES)
        wrong_action[0]["action"] = "approve"
        duplicate = refusal(separators=(",", ":")).replace('"permission":"external_directory"', '"permission":"external_directory","permission":"external_directory"', 1)
        escaped_key = refusal().replace('"permission": "external_directory"', '"perm\\u0069ssion": "external_directory"')
        for text in (refusal()[:-1], refusal({"rules": RULES}), refusal([RULES]), refusal(unknown), refusal(wrong_type), refusal(wrong_action), duplicate, escaped_key, refusal(RULES * 6), refusal() + " " * 16384):
            with self.subTest(context_length=len(text)):
                self.assertTrue(self.scan(text))

    def test_literal_variants_and_secret_like_cache_components_remain_inspected(self):
        for name in ("external_Directory", "external_directory_suffix"):
            rules = deepcopy(RULES)
            rules[2]["permission"] = name
            self.assertTrue(any(f.value == name for f in self.scan(refusal(rules))))
        paths = (
            "/" + string.ascii_lowercase[:24] + "/opencode/tool-output/*",
            "/" + "/".join(string.ascii_lowercase[index:index + 4] for index in range(0, 24, 4)) + "/opencode/tool-output/*",
            "/tmp/client1234567890/opencode/tool-output/*",
            "/tmp/CamelDirectory/opencode/tool-output/*",
            "/tmp/credential-cache/opencode/tool-output/*",
            "/tmp/../client-data/opencode/tool-output/*",
            CACHE_GLOB + "?access=example",
        )
        for path in paths:
            with self.subTest(path_length=len(path)):
                self.assertTrue(self.scan(path))
                rules = deepcopy(RULES)
                rules[2]["pattern"] = path
                self.assertTrue(any(f.value == path for f in self.scan(refusal(rules))))

    def test_other_detectors_still_inspect_accepted_literal(self):
        scanner = RegexScanner([PatternRecognizer("API_KEY", re.compile("external_directory"), 1.0)])
        firewall = Firewall(load_policy("policies/default.yaml"), scanner=scanner)
        text = refusal()
        self.assertFalse(self.scan(text))
        result = firewall.inspect(payload(text))
        self.assertTrue(result.blocked)
        self.assertTrue(any(f.detector_family == "regex" for f in result.findings))
        self.assertNotIn("external_directory", json.dumps(result.audit_event))


if __name__ == "__main__":
    unittest.main()
