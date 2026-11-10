import importlib.machinery
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fido2.webauthn import (
    AuthenticationExtensionsClientOutputs,
    AuthenticationResponse,
    AuthenticatorAssertionResponse,
    AuthenticatorData,
    CollectedClientData,
)

loader = importlib.machinery.SourceFileLoader(
    "rbw_passkey", str(Path(__file__).parents[1] / "bin" / "rbw-passkey")
)
spec = importlib.util.spec_from_loader(loader.name, loader)
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)


class PasskeyHelperTests(unittest.TestCase):
    def setUp(self):
        self.request = {
            "origin": "https://vault.example.test",
            "pin": "synthetic-test-pin",
            "options": {"userVerification": "required"},
        }

    def response(self, extensions):
        return AuthenticationResponse(
            raw_id=b"credential",
            response=AuthenticatorAssertionResponse(
                client_data=CollectedClientData.create(
                    type="webauthn.get", challenge=b"challenge",
                    origin=self.request["origin"],
                ),
                authenticator_data=AuthenticatorData(bytes(32) + b"\x05" + bytes(4)),
                signature=b"signature", user_handle=b"user",
            ),
            client_extension_results=AuthenticationExtensionsClientOutputs(extensions),
        )

    def selection(self, response):
        return SimpleNamespace(get_assertions=lambda: [object()], get_response=lambda _: response)

    def test_prf_is_kept_out_of_server_assertion(self):
        prf = "independent-prf-output"
        selection = self.selection(self.response({"prf": {"results": {"first": prf}}}))
        with patch.object(helper, "Fido2Client") as client:
            client.return_value.get_assertion.return_value = selection
            result = helper.assert_passkey(self.request, [object()])
        self.assertEqual(result["prf"], prf)
        self.assertNotIn(prf, json.dumps(result["assertion"]))
        self.assertNotIn("clientExtensionResults", result["assertion"])
        self.assertEqual(result["assertion"]["extensions"], {})

    def test_missing_prf_is_an_error(self):
        with patch.object(helper, "Fido2Client") as client:
            client.return_value.get_assertion.return_value = self.selection(self.response({}))
            with self.assertRaisesRegex(ValueError, "PRF"):
                helper.assert_passkey(self.request, [object()])

    def test_multiple_keys_and_multiple_credentials_require_selection(self):
        for devices in [[], [object(), object()]]:
            with self.assertRaisesRegex(ValueError, "exactly one"):
                helper.assert_passkey(self.request, devices)
        selection = SimpleNamespace(get_assertions=lambda: [object(), object()])
        with patch.object(helper, "Fido2Client") as client:
            client.return_value.get_assertion.return_value = selection
            with self.assertRaisesRegex(ValueError, "Multiple passkeys"):
                helper.assert_passkey(self.request, [object()])

    def test_pin_is_not_automatically_retried(self):
        interaction = helper.Interaction("synthetic-test-pin")
        self.assertEqual(interaction.request_pin(None, None), "synthetic-test-pin")
        self.assertIsNone(interaction.request_pin(None, None))

    def test_user_verification_cannot_be_disabled(self):
        self.request["options"]["userVerification"] = "discouraged"
        with self.assertRaisesRegex(ValueError, "verification"):
            helper.assert_passkey(self.request, [object()])

    def test_assertion_may_omit_its_only_allowed_credential(self):
        allowed = {"type": "public-key", "id": b"credential"}
        reply = {2: bytes(32) + b"\x05" + bytes(4), 3: b"signature"}
        ctap = SimpleNamespace(send_cbor=lambda *_args, **_kwargs: reply)
        assertion = helper.get_assertion(ctap, "example.test", bytes(32), [allowed])
        self.assertEqual(assertion.credential, allowed)
        with self.assertRaises(TypeError):
            helper.get_assertion(ctap, "example.test", bytes(32), [allowed, allowed])

    def test_reports_for_other_channels_are_skipped(self):
        theirs, ours = bytes.fromhex("0000000a") + b"stale", bytes.fromhex("0000000b") + b"reply"
        connection = SimpleNamespace(read_packet=iter([theirs, ours]).__next__)
        channel = helper.OwnChannel(SimpleNamespace(_channel_id=0x0B), connection)
        self.assertEqual(channel.read_packet(), ours)

    def test_pin_is_only_required_without_built_in_uv(self):
        cases = [
            ({"clientPin": True}, True),
            ({"clientPin": True, "uv": True}, False),
            ({"uv": True}, False),
            ({"clientPin": False}, False),
        ]
        for options, required in cases:
            with patch.object(helper, "Ctap2") as ctap2:
                ctap2.return_value.info.options = options
                self.assertEqual(helper.pin_required(object()), required, options)
        with patch.object(helper, "Ctap2", side_effect=OSError):
            with self.assertRaises(OSError):
                helper.pin_required(object())
