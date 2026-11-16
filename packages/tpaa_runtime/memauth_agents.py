"""Real AG2 agents with a secret-free memory event boundary.

Identity descriptors are local bindings, not evidence of completed MemAuth
authentication. Cryptographic keys are never injected into prompts or models.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os

from ag2 import Agent
from ag2.config import OpenAICompletionsConfig

from .memory_adapter import MemoryEvent


@dataclass(frozen=True)
class AgentBinding:
    did: str
    credential_reference: str


def build_pair(pa: AgentBinding, sa: AgentBinding, *, config=None):
    if not pa.did or not sa.did or pa.did == sa.did:
        raise ValueError('Distinct PA and SA identifiers required')
    # Binding stays in host runtime, not in model-visible prompts.
    personal = Agent('memauth_personal_agent',
                     'You are a personal research assistant. Ask the service agent to summarize '
                     'the supplied synthetic research task. Do not claim cryptographic authentication.', config=config)
    service = Agent('memauth_service_agent',
                    'You are a research summary service. Give a brief factual answer to the supplied '
                    'synthetic task. Do not claim cryptographic authentication.', config=config)
    return personal, service


def config_from_env():
    key = os.environ.get('MEMAUTH_MODEL_API_KEY', '')
    if not key:
        raise ValueError('Set MEMAUTH_MODEL_API_KEY for a real model conversation')
    return OpenAICompletionsConfig(
        model=os.environ.get('MEMAUTH_MODEL', 'deepseek-chat'), api_key=key,
        base_url=os.environ.get('MEMAUTH_MODEL_BASE_URL', 'https://api.deepseek.com/v1'),
        temperature=0.2)


async def interact(pa: AgentBinding, sa: AgentBinding, task: str, *, config):
    if type(task) is not str or not task.strip():
        raise ValueError('Nonempty synthetic task required')
    personal, service = build_pair(pa, sa, config=config)
    request = await personal.ask(task)
    outgoing = str(request.body or '')
    if not outgoing:
        raise ValueError('PA returned an empty request')
    response = await service.ask(outgoing)
    answer = str(response.body or '')
    if not answer:
        raise ValueError('SA returned an empty response')
    # Content is hashed at the adapter boundary, not exported as plaintext by default.
    def event(text, subject, action):
        return MemoryEvent(datetime.now(timezone.utc).isoformat(), action,
                           'sha256:' + hashlib.sha256(text.encode('utf-8')).hexdigest(),
                           subject, 'ag2.ask/openai-compatible')
    events = (event(outgoing, pa.did, 'agent_request'), event(answer, sa.did, 'agent_response'))
    return events, {'framework': 'ag2', 'agentClasses': [type(personal).__name__, type(service).__name__],
                    'PA': pa.did, 'SA': sa.did, 'credentialReference': pa.credential_reference,
                    'identityStatus': 'local runtime binding; full authentication not executed',
                    'requestCharacters': len(outgoing), 'responseCharacters': len(answer)}
