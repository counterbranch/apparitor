"""LiteLLM Proxy guardrail class loaded by examples/litellm/config.yaml."""

import os

from apparitor.litellm import LiteLLMAuthorizationGuardrail, LiteLLMMCPAuthorizationGuardrail


class ApparitorGuardrail(LiteLLMAuthorizationGuardrail):
    def __init__(self, **kwargs: object) -> None:
        super().__init__(pdp_url=os.environ["APPARITOR_PDP_URL"], **kwargs)


class ApparitorMCPGuardrail(LiteLLMMCPAuthorizationGuardrail):
    def __init__(self, **kwargs: object) -> None:
        super().__init__(pdp_url=os.environ["APPARITOR_PDP_URL"], **kwargs)
