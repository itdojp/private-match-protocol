from __future__ import annotations

import copy
import json
import struct
import subprocess
import sys
import tempfile
import unittest
import unicodedata
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import canonicalize_message as canonical  # noqa: E402
import validate_messages as validator  # noqa: E402


class MessageContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.message_schema = json.loads(
            (ROOT / validator.MESSAGE_SCHEMA).read_text(encoding="utf-8")
        )
        cls.timer_schema = json.loads(
            (ROOT / validator.TIMER_SCHEMA).read_text(encoding="utf-8")
        )
        cls.registry_schema = json.loads(
            (ROOT / validator.REGISTRY_SCHEMA).read_text(encoding="utf-8")
        )
        cls.material_schema = json.loads(
            (ROOT / validator.MATERIAL_SCHEMA).read_text(encoding="utf-8")
        )
        cls.registry = yaml.safe_load(
            (ROOT / validator.REGISTRY_PATH).read_text(encoding="utf-8")
        )
        cls.materials = yaml.safe_load(
            (ROOT / validator.MATERIAL_PATH).read_text(encoding="utf-8")
        )
        cls.context = yaml.safe_load(
            (ROOT / validator.CONTEXT_PATH).read_text(encoding="utf-8")
        )
        cls.valid_paths = sorted((ROOT / "conformance/messages/valid").glob("*.json"))
        cls.messages = {
            path.stem: canonical.strict_loads(path.read_bytes())
            for path in cls.valid_paths
        }

    def test_repository_message_contract_is_valid(self) -> None:
        self.assertEqual([], validator.validate_repository(ROOT))

    def test_all_json_schemas_are_valid_draft_2020_12(self) -> None:
        for schema in (
            self.message_schema,
            self.timer_schema,
            self.registry_schema,
            self.material_schema,
        ):
            Draft202012Validator.check_schema(schema)
            self.assertEqual(
                "https://json-schema.org/draft/2020-12/schema", schema["$schema"]
            )

    def test_registry_is_unique_and_fail_closed(self) -> None:
        entries = self.registry["messages"]
        names = [entry["message_type"] for entry in entries]
        self.assertEqual(18, len(names))
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual("fail-closed", self.registry["unknown_type_behavior"])
        self.assertTrue(all(entry["message_version"] == "0.1" for entry in entries))

    def test_required_message_types_are_registered(self) -> None:
        expected = {
            "session_proposal",
            "session_acceptance",
            "participant_binding",
            "policy_acceptance",
            "commitment_registration",
            "query_budget_reservation",
            "evaluation_start",
            "evaluation_contribution",
            "opaque_receipt_ack",
            "result_acceptance_notice",
            "consent_grant",
            "consent_withdrawal",
            "disclosure_extension_authorization",
            "disclosure_completion_notice",
            "abort_notice",
            "normalized_error_notice",
            "close_notice",
            "expiry_notice",
        }
        self.assertEqual(expected, set(validator._registry_index(self.registry)))

    def test_every_state_delivery_event_has_a_contract(self) -> None:
        state = yaml.safe_load(
            (ROOT / validator.STATE_MACHINE_PATH).read_text(encoding="utf-8")
        )
        self.assertEqual(
            [],
            validator.registry_findings(self.registry, state, self.message_schema),
        )

    def test_registry_parameter_sources_cover_every_required_field(self) -> None:
        state = yaml.safe_load(
            (ROOT / validator.STATE_MACHINE_PATH).read_text(encoding="utf-8")
        )
        mutated = copy.deepcopy(self.registry)
        mutated["messages"][0]["parameter_sources"].pop(0)
        findings = validator.registry_findings(
            mutated,
            state,
            self.message_schema,
        )
        self.assertIn("parameter-mapping", {item.code for item in findings})

    def test_registry_and_payload_schema_cannot_drift(self) -> None:
        state = yaml.safe_load(
            (ROOT / validator.STATE_MACHINE_PATH).read_text(encoding="utf-8")
        )
        mutated = copy.deepcopy(self.message_schema)
        mutated["$defs"]["payload_session_proposal"]["required"].remove("clock_policy")
        findings = validator.registry_findings(self.registry, state, mutated)
        self.assertIn("registry-schema-mapping", {item.code for item in findings})

    def test_timer_derived_and_local_relations_are_not_party_inputs(self) -> None:
        internal = {
            item["id"]: item for item in self.registry["internal_event_contracts"]
        }
        self.assertEqual(
            {
                "authoritative_timer_event",
                "reject_message_relation",
                "new_session_guidance",
            },
            set(internal),
        )
        self.assertTrue(
            all(not item["external_party_message"] for item in internal.values())
        )

    def test_positive_vectors_are_canonical_and_valid(self) -> None:
        self.assertGreaterEqual(len(self.valid_paths), 26)
        for path in self.valid_paths:
            raw = path.read_bytes()
            message, findings = validator.validate_message_bytes(
                raw,
                self.message_schema,
                self.registry,
                self.materials,
                self.context,
                path=path.name,
            )
            self.assertEqual([], findings, path.name)
            self.assertEqual(raw, canonical.canonicalize(message), path.name)

    def test_positive_vectors_cover_both_parties(self) -> None:
        for prefix in (
            "session-acceptance",
            "participant-binding",
            "policy-acceptance",
            "commitment-registration",
            "evaluation-contribution",
            "opaque-receipt-ack",
            "consent-grant",
            "consent-withdrawal",
        ):
            self.assertIn(f"{prefix}-a", self.messages)
            self.assertIn(f"{prefix}-b", self.messages)

    def test_all_negative_vector_expectations_are_observed(self) -> None:
        manifest = yaml.safe_load(
            (ROOT / validator.INVALID_MANIFEST).read_text(encoding="utf-8")
        )
        self.assertGreaterEqual(len(manifest["cases"]), 30)
        for case in manifest["cases"]:
            path = ROOT / "conformance/messages/invalid" / case["file"]
            _, findings = validator.validate_message_bytes(
                path.read_bytes(),
                self.message_schema,
                self.registry,
                self.materials,
                self.context,
                path=case["file"],
            )
            self.assertIn(case["expected_code"], {item.code for item in findings})

    def test_duplicate_json_key_is_rejected_before_object_construction(self) -> None:
        with self.assertRaises(canonical.DuplicateJSONKeyError):
            canonical.strict_loads(b'{"a":1,"a":2}')

    def test_nan_and_infinity_are_rejected(self) -> None:
        for raw in (b'{"n":NaN}', b'{"n":Infinity}', b'{"n":-Infinity}'):
            with self.assertRaises(canonical.CanonicalMessageError):
                canonical.strict_loads(raw)

    def test_negative_zero_is_rejected_for_integer_float_and_programmatic_input(
        self,
    ) -> None:
        for raw in (b'{"n":-0}', b'{"n":-0.0}', b'{"n":-0e0}'):
            with self.assertRaises(canonical.CanonicalMessageError):
                canonical.strict_loads(raw)
        with self.assertRaises(canonical.CanonicalMessageError):
            canonical.canonicalize({"n": -0.0})

    def test_rfc_8785_appendix_b_number_vectors(self) -> None:
        samples = {
            "0000000000000000": b"0",
            "0000000000000001": b"5e-324",
            "8000000000000001": b"-5e-324",
            "7fefffffffffffff": b"1.7976931348623157e+308",
            "ffefffffffffffff": b"-1.7976931348623157e+308",
            "44b52d02c7e14af6": b"1e+23",
            "3eb0c6f7a0b5ed8d": b"0.000001",
            "43143ff3c1cb0959": b"1424953923781206.2",
        }
        for hexadecimal, expected in samples.items():
            value = struct.unpack(">d", bytes.fromhex(hexadecimal))[0]
            self.assertEqual(expected, canonical.canonicalize(value))

    def test_rfc_8785_canonical_sample(self) -> None:
        value = {
            "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27],
            "string": '€$\u000f\nA\'B"\\\\"/',
            "literals": [None, True, False],
        }
        expected = (
            b'{"literals":[null,true,false],"numbers":[333333333.3333333,'
            b'1e+30,4.5,0.002,1e-27],"string":"\xe2\x82\xac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
        )
        self.assertEqual(expected, canonical.canonicalize(value))

    def test_unicode_is_preserved_without_normalization(self) -> None:
        nfc = unicodedata.normalize("NFC", "Cafe\u0301")
        nfd = unicodedata.normalize("NFD", nfc)
        self.assertNotEqual(canonical.canonicalize(nfc), canonical.canonicalize(nfd))
        self.assertNotEqual(
            canonical.payload_digest(nfc), canonical.payload_digest(nfd)
        )

    def test_lone_unicode_surrogate_is_a_bounded_parse_error(self) -> None:
        with self.assertRaisesRegex(
            canonical.CanonicalMessageError,
            "lone Unicode surrogate",
        ):
            canonical.strict_loads('"\ud800"')

    def test_key_order_and_whitespace_do_not_change_canonical_digest(self) -> None:
        first = canonical.strict_loads(b'{"b":2,"a":1}')
        second = canonical.strict_loads(b'{ "a" : 1, "b" : 2 }')
        self.assertEqual(canonical.canonicalize(first), canonical.canonicalize(second))
        self.assertEqual(
            canonical.payload_digest(first), canonical.payload_digest(second)
        )

    def test_payload_change_changes_payload_and_message_digest(self) -> None:
        message = self.messages["session-acceptance-a"]
        changed = copy.deepcopy(message)
        changed["payload"]["acceptance_digest"] = "sha256:" + "a" * 64
        changed = canonical.populate_digests(changed)
        self.assertNotEqual(message["payload_digest"], changed["payload_digest"])
        self.assertNotEqual(message["message_digest"], changed["message_digest"])

    def test_every_authenticated_routing_field_changes_message_digest(self) -> None:
        base = self.messages["session-acceptance-a"]
        mutations = {
            "protocol_version": lambda m: m.__setitem__("protocol_version", "9.9"),
            "message_type": lambda m: m.__setitem__(
                "message_type", "participant_binding"
            ),
            "session": lambda m: m["session_context"].__setitem__(
                "session_id", "urn:private-match:test:session:other"
            ),
            "policy": lambda m: m["session_context"]["policy"].__setitem__(
                "policy_id", "urn:private-match:test:policy:other"
            ),
            "audience": lambda m: m.__setitem__("audience", ["party_b_client"]),
            "sequence": lambda m: m["identity"].__setitem__("sequence", 99),
            "nonce": lambda m: m["identity"].__setitem__(
                "nonce", "urn:private-match:test:nonce:other"
            ),
            "prior": lambda m: m.__setitem__(
                "prior_transcript_digest", "sha256:" + "f" * 64
            ),
            "algorithm": lambda m: m["authentication"].__setitem__(
                "algorithm_id", "urn:private-match:test:algorithm:other"
            ),
            "key": lambda m: m["authentication"].__setitem__(
                "key_id", "urn:private-match:test:key:other"
            ),
            "material": lambda m: m["authentication"].__setitem__(
                "verification_material_id", "urn:private-match:test:material:other"
            ),
        }
        for name, mutate in mutations.items():
            changed = copy.deepcopy(base)
            mutate(changed)
            self.assertNotEqual(
                base["message_digest"], canonical.message_digest(changed), name
            )

    def test_authentication_value_is_the_only_authentication_field_excluded(
        self,
    ) -> None:
        message = self.messages["session-acceptance-a"]
        changed = copy.deepcopy(message)
        changed["authentication"]["value"] = "DIFFERENT-SYNTHETIC-VALUE"
        self.assertEqual(message["message_digest"], canonical.message_digest(changed))
        auth_input = canonical.authentication_input(message)
        self.assertNotIn("value", auth_input["authentication"])
        self.assertNotIn("message_digest", auth_input)
        self.assertNotIn("payload", auth_input)

    def test_coordinator_receipts_never_contain_plaintext_outcome_or_secret_input(
        self,
    ) -> None:
        for name in (
            "opaque-receipt-ack-a",
            "opaque-receipt-ack-b",
            "result-acceptance-notice",
        ):
            message = self.messages[name]
            self.assertEqual([], validator._walk_prohibited(message))
            self.assertEqual([], validator._walk_plaintext_result(message))
            rendered = canonical.canonicalize(message)
            for token in (b'"MATCH"', b'"NO_MATCH"', b'"INDETERMINATE"'):
                self.assertNotIn(token, rendered)

    def test_core_messages_never_contain_actual_disclosure_payload(self) -> None:
        for message in self.messages.values():
            self.assertNotIn(
                b"actual_disclosure_payload", canonical.canonicalize(message)
            )

    def test_party_error_notice_contains_category_not_raw_failure(self) -> None:
        notice = self.messages["normalized-error-notice"]
        self.assertIn("party_error_category", notice["payload"])
        self.assertNotIn("failure_code", notice["payload"])
        self.assertNotIn("internal_failure_code", notice["payload"])

    def test_unknown_expired_and_revoked_material_fail_closed(self) -> None:
        manifest = yaml.safe_load(
            (ROOT / validator.INVALID_MANIFEST).read_text(encoding="utf-8")
        )
        ids = {item["id"] for item in manifest["cases"]}
        self.assertTrue(
            {
                "unknown-verification-material",
                "expired-verification-material",
                "revoked-verification-material",
            }.issubset(ids)
        )

    def test_rfc8785_dependency_is_exact_and_hash_locked(self) -> None:
        direct = (ROOT / "requirements-dev.in").read_text(encoding="utf-8")
        lock = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
        self.assertIn("rfc8785==0.1.4", direct)
        self.assertIn("rfc8785==0.1.4", lock)
        self.assertIn(
            "520d690b448ecf0703691c76e1a34a24ddcd4fc5bc41d589cb7c58ec651bcd48",
            lock,
        )

    def test_workflow_preserves_minimum_permissions_and_supply_chain_controls(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/protocol-spec.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertIn("python-version: '3.12.11'", workflow)
        self.assertIn("pip install --require-hashes", workflow)
        self.assertIn("generate_message_vectors.py --root . --check", workflow)
        self.assertIn("validate_messages.py --root .", workflow)
        self.assertNotIn("upload-artifact", workflow)
        self.assertNotIn("deploy", workflow.lower())
        for line in workflow.splitlines():
            if "uses:" not in line:
                continue
            reference = line.split("@", 1)[1].split()[0]
            self.assertRegex(reference, r"^[0-9a-f]{40}$")
            self.assertRegex(line, r"# v\d")

    def test_cli_parse_failure_is_bounded_without_traceback(self) -> None:
        path = ROOT / "conformance/messages/invalid/duplicate-json-key.json"
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/validate_messages.py"),
                "--root",
                str(ROOT),
                "--file",
                str(path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(1, result.returncode)
        self.assertIn("json-parse", result.stdout)
        self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_canonicalizer_cli_emits_exact_jcs_bytes_without_delimiter(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "input.json"
            path.write_bytes(b'{ "b": 2, "a": 1 }')
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/canonicalize_message.py"), path],
                check=False,
                capture_output=True,
            )
        self.assertEqual(0, result.returncode)
        self.assertEqual(b'{"a":1,"b":2}', result.stdout)
        self.assertEqual(b"", result.stderr)


if __name__ == "__main__":
    unittest.main()
