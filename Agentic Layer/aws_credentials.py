"""Validate AWS credentials with STS GetCallerIdentity (read-only, no AWS resources touched).

Used by the Settings page "Validate credentials" button. Secrets are only passed to boto3
and are never logged or echoed back.
"""
from __future__ import annotations

from typing import Any, Callable


def _default_sts_client(access_key: str, secret_key: str, region: str):
    import boto3
    from botocore.config import Config

    session = boto3.session.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )
    return session.client(
        "sts",
        config=Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 1}),
    )


# botocore error codes that mean "these credentials are wrong", as opposed to a transport problem
_BAD_CREDENTIAL_CODES = {
    "InvalidClientTokenId": "The access key ID is not recognised by AWS.",
    "SignatureDoesNotMatch": "The secret access key does not match the access key ID.",
    "AuthFailure": "AWS rejected the credentials.",
    "ExpiredToken": "The credentials have expired.",
    "InvalidToken": "The credentials are not valid.",
}


def validate_aws_credentials(
    access_key_id: str,
    secret_access_key: str,
    region: str = "us-east-1",
    client_factory: Callable[[str, str, str], Any] | None = None,
) -> dict[str, Any]:
    """Return {"valid": bool, "account", "arn", "user_id", "error"}.

    Never raises: any failure becomes valid=False with a human-readable error.
    """
    access_key_id = (access_key_id or "").strip()
    secret_access_key = (secret_access_key or "").strip()
    result: dict[str, Any] = {"valid": False, "account": None, "arn": None, "user_id": None, "error": None}

    if not access_key_id or not secret_access_key:
        result["error"] = "Both the access key ID and the secret access key are required."
        return result

    try:
        client = (client_factory or _default_sts_client)(access_key_id, secret_access_key, region or "us-east-1")
        identity = client.get_caller_identity()
    except Exception as exc:  # noqa: BLE001 - boto3 raises many exception types
        code = ""
        response = getattr(exc, "response", None)
        if isinstance(response, dict):
            code = str((response.get("Error") or {}).get("Code") or "")
        if code in _BAD_CREDENTIAL_CODES:
            result["error"] = _BAD_CREDENTIAL_CODES[code]
        elif type(exc).__name__ in {"EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError", "ConnectionClosedError"}:
            result["error"] = "Could not reach AWS STS from the server (network error or timeout)."
        else:
            # Keep the message short and make sure the secret can never leak through it.
            message = str(exc).replace(secret_access_key, "***").replace(access_key_id, "***")
            result["error"] = f"AWS validation failed: {message[:200]}"
        return result

    result.update(
        valid=True,
        account=identity.get("Account"),
        arn=identity.get("Arn"),
        user_id=identity.get("UserId"),
    )
    return result
