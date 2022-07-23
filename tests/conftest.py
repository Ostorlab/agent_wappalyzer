"""Fixutes for Wappalyzer agent."""
import pathlib
import random

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent import message
from ostorlab.runtimes import definitions as runtime_definitions

from agent import wappalyzer_agent


@pytest.fixture
def domain_message():
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.domain_name'
    msg_data = {
        'name': 'test.ostorlab.co',
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def https_link_message():
    """Creates a dummy message of type v3.asset.link to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.link'
    msg_data = {
        'url': 'https://ostorlab.co',
        'method': 'GET'
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def http_link_message():
    """Creates a dummy message of type v3.asset.link to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.link'
    msg_data = {
        'url': 'http://ostorlab.co',
        'method': 'GET'
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def wappalyzer_test_agent():
    with (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/wappalyzer',
            bus_url='NA',
            bus_exchange_topic='NA',
            redis_url='redis://redis',
            args=[],
            healthcheck_port=random.randint(4000, 5000))
        return wappalyzer_agent.AgentWappalyzer(definition, settings)
