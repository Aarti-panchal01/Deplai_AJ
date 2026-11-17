import asyncio
from unittest.mock import patch

import param_selector
from param_selector import select_params


async def _select() -> dict:
    return await select_params(
        service_type="ec2",
        repo_context={"language": "python", "framework": "fastapi", "project_name": "myapp"},
        user_customizations={"instance_type": "t3.micro"},
        aws_region="us-east-1",
        project_id="proj-test-001",
    )


def test_select_params_deterministic_fallback() -> None:
    """With the LLM unavailable, select_params must fall back to deterministic params."""

    async def _fail_llm(*args, **kwargs):
        raise RuntimeError("LLM unavailable in tests")

    with patch.object(param_selector, "_call_llm", _fail_llm):
        params = asyncio.run(_select())

    assert "instance_name" in params
    assert "instance_type" in params
    assert params["aws_region"] == "us-east-1"
    assert params["project_id"] == "proj-test-001"
