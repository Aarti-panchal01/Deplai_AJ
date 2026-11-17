"""Tests for IaC pipeline bug fixes.

Covers:
- Fix 1: project_id scope in run_pipeline (formerly _execute_run)
- Fix 2: terraform_agent package importability
- Fix 7: .env.template documents ANTHROPIC_API_KEY
- Fix 8: All eight Terraform template directories exist
- Property 3: project_id forwarding in run_pipeline
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Fix 1: run_pipeline must forward project_id
# ---------------------------------------------------------------------------

class TestRunPipelineProjectId:
    """Verify run_pipeline forwards project_id to select_params and validate_with_retry."""

    def _run_pipeline(self, project_id: str) -> dict:
        """Helper: run run_pipeline with all phases mocked and return captured args."""
        from agent.iac_pipeline import run_pipeline

        captured: dict = {}

        async def mock_select_params(service_type, repo_context, user_customizations, aws_region, project_id):
            captured["select_params_pid"] = project_id
            return {"instance_name": "test", "aws_region": "us-east-1"}

        async def mock_validate(service_type, params, project_id, aws_credentials, **kwargs):
            captured["validate_pid"] = project_id
            return (Path("/tmp/ws"), params)

        async def mock_plan(workspace, creds):
            return "Plan: 1 to add."

        async def mock_stream_apply(workspace, creds, run_id):
            return
            yield  # make it an async generator

        async def mock_get_outputs(workspace, creds):
            return {"public_ip": "1.2.3.4"}

        def mock_parse_outputs(raw, service):
            return raw

        def mock_extract_keypair(path):
            return None

        async def _run():
            with (
                patch("agent.iac_pipeline.select_params", mock_select_params),
                patch("agent.iac_pipeline.validate_with_retry", mock_validate),
                patch("agent.iac_pipeline.plan", mock_plan),
                patch("agent.iac_pipeline.stream_apply", mock_stream_apply),
                patch("agent.iac_pipeline.get_outputs", mock_get_outputs),
                patch("agent.iac_pipeline.parse_outputs", mock_parse_outputs),
                patch("agent.iac_pipeline.extract_keypair_details", mock_extract_keypair),
            ):
                run = await run_pipeline(
                    project_id=project_id,
                    service_type="ec2",
                    repo_context={},
                    user_customizations={},
                    aws_credentials={},
                    aws_region="us-east-1",
                )
            captured["status"] = run.status
            captured["error"] = run.error
            return captured

        return asyncio.run(_run())

    def test_run_pipeline_forwards_project_id(self):
        """select_params and validate_with_retry must receive the project_id."""
        from agent.iac_pipeline import RunStatus

        captured = self._run_pipeline("test-proj")
        assert captured["error"] is None
        assert captured["status"] == RunStatus.COMPLETED
        assert captured["select_params_pid"] == "test-proj"
        assert captured["validate_pid"] == "test-proj"

    def test_run_pipeline_empty_project_id_does_not_fail(self):
        """Empty project_id must not raise NameError or fail the run."""
        from agent.iac_pipeline import RunStatus

        captured = self._run_pipeline("")
        assert captured["error"] is None
        assert captured["status"] == RunStatus.COMPLETED
        assert captured["select_params_pid"] == ""
        assert captured["validate_pid"] == ""


# ---------------------------------------------------------------------------
# Fix 2: terraform_agent package importability
# ---------------------------------------------------------------------------

class TestTerraformAgentImportable:
    """Verify the terraform_agent package can be imported."""

    def test_terraform_agent_importable(self):
        """import terraform_agent must not raise ModuleNotFoundError."""
        import terraform_agent  # noqa: F401

    def test_iac_pipeline_importable(self):
        """from terraform_agent.agent.iac_pipeline import IaCRun must work."""
        from terraform_agent.agent.iac_pipeline import IaCRun  # noqa: F401
        assert IaCRun is not None


# ---------------------------------------------------------------------------
# Fix 8: All eight Terraform template directories exist
# ---------------------------------------------------------------------------

EXPECTED_SERVICES = ["ec2", "s3", "rds", "vpc", "ecs", "lambda", "elasticache", "alb"]
TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"


class TestTemplateDirectoriesExist:
    """Verify all eight service template directories are present and complete."""

    @pytest.mark.parametrize("service", EXPECTED_SERVICES)
    def test_template_directory_exists(self, service: str):
        template_dir = TEMPLATES_DIR / service
        assert template_dir.is_dir(), f"Template directory missing: {template_dir}"

    @pytest.mark.parametrize("service", EXPECTED_SERVICES)
    def test_main_tf_exists(self, service: str):
        assert (TEMPLATES_DIR / service / "main.tf").is_file(), \
            f"main.tf missing for {service}"

    @pytest.mark.parametrize("service", EXPECTED_SERVICES)
    def test_variables_tf_exists(self, service: str):
        assert (TEMPLATES_DIR / service / "variables.tf").is_file(), \
            f"variables.tf missing for {service}"

    @pytest.mark.parametrize("service", EXPECTED_SERVICES)
    def test_outputs_tf_exists(self, service: str):
        assert (TEMPLATES_DIR / service / "outputs.tf").is_file(), \
            f"outputs.tf missing for {service}"


# ---------------------------------------------------------------------------
# Fix 7: .env.template documents ANTHROPIC_API_KEY
# ---------------------------------------------------------------------------

ENV_TEMPLATE_PATH = Path(__file__).resolve().parents[3] / ".env.template"


class TestEnvTemplateDocumentation:
    """Verify .env.template documents the IaC pipeline LLM variables."""

    def test_anthropic_api_key_present(self):
        content = ENV_TEMPLATE_PATH.read_text(encoding="utf-8")
        assert "ANTHROPIC_API_KEY=" in content, \
            "ANTHROPIC_API_KEY= entry missing from .env.template"

    def test_anthropic_api_key_has_param_selector_comment(self):
        content = ENV_TEMPLATE_PATH.read_text(encoding="utf-8")
        assert "param_selector" in content, \
            ".env.template should reference param_selector.py in ANTHROPIC_API_KEY comment"

    def test_iac_param_selector_model_documented(self):
        content = ENV_TEMPLATE_PATH.read_text(encoding="utf-8")
        assert "IAC_PARAM_SELECTOR_MODEL" in content, \
            "IAC_PARAM_SELECTOR_MODEL should be documented in .env.template"
