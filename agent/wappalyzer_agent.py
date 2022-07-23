"""Wappalyzer Agent: Agent responsible for fingerprinting a website."""
import json
import logging
import subprocess
from urllib import parse
import dataclasses
from typing import Optional, Dict

from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent import message as m
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True), ],
    level='INFO',
    force=True
)
logger = logging.getLogger(__name__)

VULNZ_TITLE = 'Web Tech Stack Fingerprint'
VULNZ_ENTRY_RISK_RATING = 'INFO'
VULNZ_SHORT_DESCRIPTION = 'List of web technologies recognized'
VULNZ_DESCRIPTION = """Lists web technologies including content management systems(CMS), blogging platforms,
statistic/analytics packages, JavaScript libraries, web servers, embedded devices, version numbers, email addresses,
account IDs, web framework modules, SQL errors, and more."""
DEFAULT_FINGERPRINT = 'BACKEND_COMPONENT'
LIB_SELECTOR = 'v3.fingerprint.domain_name.service.library'

CWD = '/wappalyzer'
SCHEME_TO_PORT = {'http': 80, 'https': 443}


@dataclasses.dataclass
class Target:
    url: str
    domain: str
    port: Optional[int] = None
    schema: Optional[str] = None


class AgentWappalyzer(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin,
                      persist_mixin.AgentPersistMixin):
    """Agent responsible for fingerprinting a website."""

    def __init__(self, agent_definition: agent_definitions.AgentDefinition,
                 agent_settings: runtime_definitions.AgentSettings) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        agent_report_vulnerability_mixin.AgentReportVulnMixin.__init__(self)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)
        self._port = self.args.get('port')
        self._is_https = self.args.get('https')

    def process(self, message: m.Message) -> None:
        """Starts a Wappalyzer scan, wait for the scan to finish,
        and emit the results.
        Args:
            message:  The message to process from ostorlab runtime.
        """
        logger.info('processing message of selector : %s', message.selector)
        target = self._prepare_target(message)

        if not self.set_add(b'agent_wappalyzer_asset', target.url):
            logger.info('target %s/ was processed before, exiting', target.url)
            return

        fingerprints = self._start_scan(target.url)
        if fingerprints is not None:
            self._parse_emit_result(target, fingerprints)

    def _prepare_target(self, message: m.Message) -> Target:
        """Prepare targets based on type, if a domain name is provided,
        port and protocol are collected from the config."""
        if message.data.get('url'):
            target = self._prepare_target_from_link_msg(message)
        elif message.data.get('name'):
            target = self._prepare_target_from_domain_msg(message)
        else:
            raise NotImplementedError(f'Message selector {message.selector} not supported.')

        return target

    def _prepare_target_from_domain_msg(self, domain_message: m.Message) -> Target:
        """Prepare target from domain message."""
        if self._is_https is True:
            schema = 'https'
            port = self._port if self._port != 443 else 443
        else:
            schema = 'http'
            port = self._port if self._port != 80 else 80
        domain_name = domain_message.data['name']
        url = f'{schema}://{domain_name}:{port}'
        target = Target(url=url, domain=domain_name, schema=schema, port=port)
        return target

    def _prepare_target_from_link_msg(self, url_message: m.Message) -> tuple:
        """Prepare target from link message."""
        url = url_message.data['url']
        parsed_url = parse.urlparse(url)
        schema = parsed_url.scheme
        arg_schema = 'https' if self._is_https is True else 'http'
        schema = schema or arg_schema
        port = 0
        domain_name = parsed_url.netloc
        if len(parsed_url.netloc.split(':')) > 1:
            port = parsed_url.netloc.split(':')[-1]
            domain_name = parsed_url.netloc.split(':')[0]
        port = int(port) or SCHEME_TO_PORT.get(schema) or self._port
        target = Target(url=url, domain=domain_name, schema=schema, port=port)
        return target

    def _start_scan(self, url: str) -> Optional[Dict]:
        """Run a Wappalyzer scan using python subprocess.
        Args:
            url: Target domain name.
        """
        logger.info('Staring a new scan for %s .', url)
        command = ['node', 'src/drivers/npm/cli.js', url]
        output = subprocess.run(command, cwd=CWD, capture_output=True, check=False)
        if output.returncode == 0:
            return json.loads(output.stdout.decode())
        else:
            return None

    def _parse_emit_result(self, target: Target, fingerprints: Dict):
        """After the scan is done, parse the output json file into a dict of the scan findings."""
        for tech in fingerprints.get('technologies', []):
            name = tech.get('name')
            version = tech.get('version')
            categories = tech.get('categories')
            if categories:
                library_type = categories[0]['name']
            else:
                library_type = None
            self._send_detected_fingerprints(target, name, version, library_type)

    def _send_detected_fingerprints(self, target: Target, name: str,
                                    version: Optional[str], library_type: Optional[str]):
        """Emits the identified fingerprints.
        Args:
            url: The URL when fingerprint is collected.
            name: Library name.
            version: The version identified by Wappalyzer scanner.
            library_type: The first category returned the Wappalyzer scanner.
        """
        url = target.url
        logger.info('found fingerprint %s %s %s %s', url, name, version, library_type)
        msg_data = {
            'name': url,
            'port': target.port,
            'schema': target.schema,
            'library_name': name,
            'library_version': version or '',
            'library_type': library_type or '',
            'detail': f'Wappalyzer Detected {name} on {url}'
        }
        self.emit(selector=LIB_SELECTOR, data=msg_data)
        self.report_vulnerability(
            entry=kb.Entry(
                title=VULNZ_TITLE,
                risk_rating=VULNZ_ENTRY_RISK_RATING,
                short_description=VULNZ_SHORT_DESCRIPTION,
                description=VULNZ_DESCRIPTION,
                references={},
                security_issue=True,
                privacy_issue=False,
                has_public_exploit=False,
                targeted_by_malware=False,
                targeted_by_ransomware=False,
                targeted_by_nation_state=False
            ),
            technical_detail=f'Found library `{name}`, version `{version or "unknown"}`, '
                             f'of type `{library_type}` in domain `{url}`',
            risk_rating=agent_report_vulnerability_mixin.RiskRating.INFO)


if __name__ == '__main__':
    logger.info('Wappalyzer agent starting ...')
    AgentWappalyzer.main()
