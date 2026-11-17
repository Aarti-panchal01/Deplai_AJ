import asyncio
import shutil

import pytest

from validator import validate_with_retry


async def _validate() -> None:
    bad_params = {
        "instance_name": "test-box",
        "instance_type": "zzz.invalid",
        "aws_region": "us-east-1",
        "ami_id": "",
        "key_pair_name": "deplai-keypair",
        "root_volume_size_gb": 20,
        "environment": "production",
        "project_id": "proj-test-001",
    }
    fake_creds = {
        "access_key_id": "AKIATEST",
        "secret_access_key": "testsecret",
        "region": "us-east-1",
    }
    workspace, final_params = await validate_with_retry(
        service_type="ec2",
        params=bad_params,
        project_id="proj-test-001",
        aws_credentials=fake_creds,
    )
    print("Validated workspace:", workspace)
    print("Final params:", final_params)


@pytest.mark.skipif(shutil.which("terraform") is None, reason="requires the terraform binary on PATH")
def test_validate_with_retry_integration() -> None:
    """Integration check: needs a real terraform binary; run it where terraform is installed."""
    asyncio.run(_validate())
