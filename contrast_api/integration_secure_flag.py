

import requests

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from rich import print
from rich.logging import RichHandler

from contrast_api.models import Rule
from contrast_api.integrations_helper import Integration

import logging
logger = logging.getLogger(__name__)


def get_info_from_secureflag_api():
    """Get SecureFlag info for a given CWE number from the SecureFlag API"""
    url = f"https://knowledge-base.secureflag.com/_vulnerabilities/labs.json"
    
    headers = {
        "Content-Type": "application/json"
    }

    logger.debug(f"Getting SecureFlag info")
    try: 
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        secureflag_cwe_data = response.json()
    except requests.exceptions.RequestException as err:
            logger.error(f"An error occurred when fetching data from {url}: {err}")
            raise Exception(err)

    # print(type(secureflag_cwe_data))
    secureflag_cwe_info_parent = []
    secureflag_cwe_info_childern = []

    for cwe in secureflag_cwe_data:
        secureflag_labs = []
        for lab in cwe.get("labs"):
            secureflag_lab = SecureFlagLab(
                title = lab.get("title"),
                lab_url = lab.get("lab_url"),
                lab_uuid = lab.get("lab_uuid"),
            )
            secureflag_labs.append(secureflag_lab)

        # First generate a full list of SF Info Objects
        secureflag_info = SecureFlagInfo(
            vulnerability = cwe.get("vulnerability"),
            category = cwe.get("category"),
            technology = cwe.get("technology"),
            cwe_number = cwe.get("CWE"),
            asvs = cwe.get("ASVS"),
            html_url = cwe.get("html_url"),
            markdown_url = cwe.get("markdown_url"),
            labs = secureflag_labs,
        )
        
        if secureflag_info.technology == "Agnostic":
            # Ignore any duplicates (there are duplicates!!)
            if secureflag_info not in secureflag_cwe_info_parent:
                secureflag_cwe_info_parent.append(secureflag_info)
        else: 
            # Ignore any duplicates (there are duplicates!!)
            if secureflag_info not in secureflag_cwe_info_childern:
                secureflag_cwe_info_childern.append(secureflag_info)

    for child in secureflag_cwe_info_childern:
        for parent in secureflag_cwe_info_parent:
            if child.vulnerability == parent.vulnerability:
                parent.other_languages.append(child.technology)

    return secureflag_cwe_info_parent


@dataclass
class SecureFlagLab:
    title: str
    lab_url: str
    lab_uuid: str


@dataclass
class SecureFlagInfo:
    vulnerability: str
    category: str
    technology: str
    cwe_number: int
    asvs: str
    html_url: str
    markdown_url: str
    labs: List[SecureFlagLab]
    other_languages: List[str] = field(default_factory=list) 


import functools

class SecureFlagIntegration(Integration):
    """Inherits from Integration class to provide SCW integration.
    Requires a name of 'SCW' and a template for the SCW integration block. 
    Overwrite the _get_integration_data method to provide the SCW data.
    """
        
    # Because we get all the data every time we query the SecureFlag API we can just store it in memory when the class is initialised
    @functools.cached_property
    def _integration_data(self):
        self._integration_data = get_info_from_secureflag_api()
        return self._integration_data

    def _get_info_by_cwe(self, cwe_number_to_find): 
        for sf_info_item in self._integration_data:
            for cwe in sf_info_item.cwe_number:
                if cwe == cwe_number_to_find:
                    self._logger.debug(f"[green]Found SecureFlag info by CWE number {cwe_number_to_find}")
                    return sf_info_item

    def _get_info_by_name(self, name_to_find): 
        for sf_info_item in self._integration_data:
            if sf_info_item.vulnerability == name_to_find:
                self._logger.debug(f"[yellow]Found SecureFlag info by Reserve mapping via SecureFlag vulnerability name '{name_to_find}'")
                return sf_info_item

    def _get_integration_data(self, rule):
        """
        Get SecureFlag info for a given Contrast policy rule.
        """
        # If the policy.name is in OVERRIDES, use the alternative mapping key
        if rule.name in OVERRIDES.keys():
            self._logger.warn(f"[yellow]Using override {OVERRIDES[rule.name]} for rule '{rule.name}'")
            # Search for a sf_cwe objection based on sf_name
            data_for_rule = self._get_info_by_name(OVERRIDES[rule.name])
        # If the policy.name is in RESERVES, use the alternative mapping key
        elif rule.name in RESERVES.keys():
            # Search for a sf_cwe objection based on sf_name
            data_for_rule = self._get_info_by_name(RESERVES[rule.name])
        # Else, search by CWE number
        else:
            data_for_rule = self._get_info_by_cwe(rule.cwe_number)

        if data_for_rule:
            return data_for_rule
        else: 
            self._logger.error(f"[red]No SecureFlag data found AND no RESERVE MAPPING for rule '{rule.name}': [/red][gray]{rule.description}")
            return None


# Override the mapping from CWE to SCW mapping if a better option exists
OVERRIDES = {}

# Add any SCW references that are not already in the CWE mapping
# Maps CWE numbers to the SCW default MappingKey
RESERVES = {
    "cache-controls-missing": "Sensitive Information Disclosure",
    "cache-control-disabled": "Sensitive Information Disclosure",
    "cookie-flags-missing": "Insufficient Transport Layer Security",
    "cookie-header-missing-flags": "Insufficient Transport Layer Security",
    "unvalidated-forward": "Open Redirect",
    "authorization-rules-misordered": "Broken Authorization",
    "authorization-missing-deny": "Broken Authorization",
    "custom-errors-off": "Sensitive Information Disclosure",
    "expression-language-injection": "Insufficient Input Validation",
    "forms-auth-ssl": "Unchecked Origin in postMessage",
    "autocomplete-missing": "Incorrect Content Security Policy",
    "hardcoded-key": "Sensitive Information Disclosure",
    "hardcoded-password": "Sensitive Information Disclosure",
    "header-checking-disabled": "Incorrect Access-Control Headers",
    "hql-injection": "SQL Injection",
    "http-only-disabled": "Lack of Content Type Headers",
    "insecure-jsp-access": "Insecure Functionality Exposed",
    "insecure-socket-factory": "Weak Cipher",
    "jndi-injection": "Log Injection",
    "ldap-injection": "Insufficient Input Validation",
    "log-injection": "Log Injection",
    "smtp-injection": "Insufficient Input Validation",
    "overly-permissive-cross-domain-policy": "Incorrect Content Security Policy",
    "clickjacking-control-missing": "UI Redressing",
    "parameter-pollution": "Cross-Site Request Forgery",
    "prompt-injection": "Insufficient Input Validation",
    "plaintext-conn-strings": "Sensitive Information Disclosure",
    "rails-http-only-disabled": "Lack of Content Type Headers",
    "reflection-injection": "Insufficient Input Validation",
    "redos": "Lack of Resources and Rate Limiting",
    "hsts-header-missing": "Insufficient Transport Layer Security",
    "xcontenttype-header-missing": "Lack of Content Type Headers",
    "role-manager-protection": "Broken Authorization",
    "role-manager-ssl": "Insufficient Transport Layer Security",
    "httponly": "Lack of Content Type Headers",
    "crypto-weak-randomness": "Weak Cipher",
    "compilation-debug": "Insecure Functionality Exposed",
    "secure-flag-missing": "Insufficient Transport Layer Security",
    "trace-enabled": "Sensitive Information Disclosure",
    "trace-enabled-aspx": "Sensitive Information Disclosure",
    "trust-boundary-violation": "Broken Session Management",
    "verb-tampering": "HTTP Response Splitting",
    "wcf-exception-details": "Sensitive Information Disclosure",
    "wcf-metadata-enabled": "Sensitive Information Disclosure",
    "unsafe-xml-decode": "XML Entity Expansion",
    "xpath-injection": "XML Entity Expansion",
}


# SECURE FLAG TEMPLATE
template = """
{% raw %}
    {{#header}}Secure Flag {{#omitted}} Integration{{/omitted}}{{/header}}
    {{#paragraph}}Learn more about {{#focus}}{% endraw %}{{ policy_info.title }}{% raw %}{{/focus}} vulnerabilities over on the Secure Flag platform by reading knowledge base articles and completing training labs that focus on secure coding.{{/paragraph}}
    {% endraw %}
{% if integration_info.html_url %}{% raw %}
{{#unorderedList}}
    {{#listElement}}
        {{#linkExternal}}{% endraw %}{{ integration_info.html_url }}{% raw %}$$LINK_DELIM$$Secure Flag Knowledge Base: {% endraw %}{{ integration_info.vulnerability }}{% raw %}{{/linkExternal}}
    {{/listElement}}{% endraw %}
{% endif %}
{% if integration_info.labs %}
    {% for lab in integration_info.labs %}{% raw %}
            {{#listElement}}
                {{#linkExternal}}{% endraw %}{{ lab.lab_url }}$$LINK_DELIM$$Secure Flag Lab: {{ lab.title }}{% raw %}{{/linkExternal}}
            {{/listElement}}{% endraw %}
    {% endfor %}
{% endif %}
{% raw %}{{/unorderedList}}{% endraw %}
"""
