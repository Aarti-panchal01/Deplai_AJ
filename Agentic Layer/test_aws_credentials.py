from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from aws_credentials import validate_aws_credentials  # noqa: E402


class _ClientError(Exception):
    def __init__(self, code: str, message: str = "boom"):
        super().__init__(message)
        self.response = {"Error": {"Code": code, "Message": message}}


class EndpointConnectionError(Exception):
    pass


def _factory(identity=None, error=None):
    class Client:
        def get_caller_identity(self):
            if error:
                raise error
            return identity

    calls = []

    def make(access_key, secret_key, region):
        calls.append((access_key, secret_key, region))
        return Client()

    make.calls = calls
    return make


class ValidateAwsCredentialsTests(unittest.TestCase):
    def test_valid_credentials_return_identity(self):
        make = _factory({"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/me", "UserId": "AIDAX"})
        result = validate_aws_credentials("AKIAEXAMPLE", "secret", "eu-west-1", client_factory=make)
        self.assertTrue(result["valid"])
        self.assertEqual(result["account"], "123456789012")
        self.assertEqual(result["arn"], "arn:aws:iam::123456789012:user/me")
        self.assertIsNone(result["error"])
        self.assertEqual(make.calls, [("AKIAEXAMPLE", "secret", "eu-west-1")])

    def test_missing_keys_are_rejected_without_calling_aws(self):
        make = _factory({})
        for access, secret in (("", ""), ("AKIA", ""), ("", "secret"), ("  ", "  ")):
            result = validate_aws_credentials(access, secret, client_factory=make)
            self.assertFalse(result["valid"])
            self.assertIn("required", result["error"])
        self.assertEqual(make.calls, [])

    def test_bad_credentials_give_specific_messages(self):
        cases = {
            "InvalidClientTokenId": "access key ID",
            "SignatureDoesNotMatch": "secret access key",
            "ExpiredToken": "expired",
        }
        for code, fragment in cases.items():
            result = validate_aws_credentials("AKIA", "s", client_factory=_factory(error=_ClientError(code)))
            self.assertFalse(result["valid"])
            self.assertIn(fragment, result["error"])

    def test_network_errors_are_reported_as_such(self):
        result = validate_aws_credentials("AKIA", "s", client_factory=_factory(error=EndpointConnectionError("dns")))
        self.assertFalse(result["valid"])
        self.assertIn("Could not reach AWS", result["error"])

    def test_unknown_errors_never_leak_the_secret(self):
        secret = "SUPERSECRETKEYVALUE123"
        error = RuntimeError(f"weird failure for AKIAEXAMPLE using {secret}")
        result = validate_aws_credentials("AKIAEXAMPLE", secret, client_factory=_factory(error=error))
        self.assertFalse(result["valid"])
        self.assertNotIn(secret, result["error"])
        self.assertNotIn("AKIAEXAMPLE", result["error"])

    def test_client_construction_errors_are_handled(self):
        def broken(*_args):
            raise ValueError("bad region")

        result = validate_aws_credentials("AKIA", "s", client_factory=broken)
        self.assertFalse(result["valid"])
        self.assertIn("bad region", result["error"])


if __name__ == "__main__":
    unittest.main()
