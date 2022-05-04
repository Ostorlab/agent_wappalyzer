"""Wappalyzer Agent: Agent responsible for fingerprinting a website."""

import logging
import subprocess
import json
from typing import Optional, Dict

from ostorlab.agent import agent
from ostorlab.agent import message as m
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
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
LIB_SELECTOR = 'v3.fingerprint.domain_name.library'

CWD = '/wappalyzer'


class AgentWappalyzer(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """Agent responsible for fingerprinting a website."""

    def process(self, message: m.Message) -> None:
        """Starts a Wappalyzer scan, wait for the scan to finish,
        and emit the results.
        Args:
            message:  The message to process from ostorlab runtime.
        """
        logger.info('processing message of selector : %s', message.selector)
        target = self._prepare_target(message)
        fingerprints = self._start_scan(target)
        if fingerprints is not None:
            self._parse_emit_result(target, fingerprints)

    def _prepare_target(self, message: m.Message) -> str:
        """Prepare targets based on type, if a domain name is provided, port and protocol are collected from the config.
        """
        domain_name = message.data.get('name')
        https = self.args.get('https')
        port = self.args.get('port')
        if https is True and port != 443:
            return f'https://{domain_name}:{port}'
        elif https is True:
            return f'https://{domain_name}'
        elif port == 80:
            return f'http://{domain_name}'
        else:
            return f'http://{domain_name}:{port}'

    def _start_scan(self, url: str) -> Optional[Dict]:
        """Run a Wappalyzer scan using python subprocess.
        Args:
            url: Target domain name.
        """
        logger.info('Staring a new scan for %s .', url)
        command = ['node', 'src/drivers/npm/cli.js' , url]
        output = subprocess.run(command, cwd=CWD, capture_output=True, check=False)
        print(output)
        if output.returncode == 0:
            return json.loads(output.stdout.decode())
        else:
            return None

    def _parse_emit_result(self, url: str, fingerprints: Dict):
        """After the scan is done, parse the output json file into a dict of the scan findings."""
        for tech in fingerprints.get('technologies', []):
            slug = tech.get('slug')
            name = tech.get('name')
            confidence = tech.get('confidence')
            version = tech.get('version')
            icon = tech.get('icon')
            website = tech.get('website')
            cpe = tech.get('cpe')
            categories = tech.get('categories')
            self._send_detected_fingerprints()

    def _send_detected_fingerprints(self, domain_name: str, library_name: str, versions: list):
        """Emits the identified fingerprints.
        Args:
            domain_name: The domain name.
            library_name: Library name.
            versions: The versions identified by Wappalyzer scanner.
        """
        logger.info('found fingerprint %s %s %s', domain_name, library_name, versions)
        fingerprint_type = FINGERPRINT_TYPE[
            library_name.lower()] if library_name.lower() in FINGERPRINT_TYPE else DEFAULT_FINGERPRINT
        if len(versions) > 0:
            for version in versions:
                msg_data = {
                    'domain_name': domain_name,
                    'library_name': library_name,
                    'library_version': str(version),
                    'library_type': fingerprint_type
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
                    technical_detail=f'Found library `{library_name}`, version `{str(version)}`, '
                    f'of type `{fingerprint_type}` in domain `{domain_name}`',
                    risk_rating=agent_report_vulnerability_mixin.RiskRating.INFO)
        else:
            # No version is found.
            msg_data = {
                'domain_name': domain_name,
                'library_name': library_name,
                'library_version': '',
                'library_type': fingerprint_type
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
                technical_detail=f'Found library `{library_name}` of type '
                f'`{fingerprint_type}` in domain `{domain_name}`',
                risk_rating=agent_report_vulnerability_mixin.RiskRating.INFO)


if __name__ == '__main__':
    logger.info('Wappalyzer agent starting ...')
    AgentWappalyzer.main()