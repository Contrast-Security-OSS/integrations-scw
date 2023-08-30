
import requests
from rich import print
from rich.console import Console
console = Console()
from rich import traceback
traceback.install(console=console, theme="monokai")

from dataclasses import dataclass

from contrast_api.models import Rule
from contrast_api.integrations_helper import Integration

import logging
logger = logging.getLogger(__name__)


class NoSCWInfoException(Exception):
    pass


def get_info_from_scw_api(mapping_key: str, mapping_list: str = "cwe"):
    """Get SCW info for a given CWE number from the SCW API"""
    url = f"https://integration-api.securecodewarrior.com/api/v1/trial?Id=contrast&MappingList={mapping_list}&MappingKey={mapping_key}&redirect=false"
    
    headers = {
        "Content-Type": "application/json"
    }

    logger.debug(f"Getting SCW info for CWE: {mapping_key}")
    try:
        response = requests.get(url, headers=headers)
        scw_cve_data = response.json()
        return scw_cve_data
    except requests.exceptions.RequestException as err:
            logger.error(f"An error occurred when fetching data from {url}: {err}")
            raise Exception(err)


@dataclass
class ScwInfo:
    contrast_rule_name: str
    cwe_number: int
    url: str
    name: str
    description: str
    video_links: str
    links: list


class SCWIntegration(Integration):
    """Inherits from Integration class to provide SCW integration.
    
    Requires a name of 'SCW' and a template for the SCW integration block. 
    Overwrite the _get_integration_data method to provide the SCW data.
    """

    def _get_integration_data(self, rule):
        """Get SCW info for a given Contrast policy rule.
    
        If the policy rule is not in the CWE mapping, use the RESERVES mapping.
        Allows overriding the CWE mapping with the OVERRIDES mapping.
        """
        # If the policy.name is in OVERRIDES, use the alternative mapping key
        if rule.name in OVERRIDES.keys():
            self._logger.debug(f"[yellow]Using override {OVERRIDES[rule.name]} for rule '{rule.name}'")
            scw_data = get_info_from_scw_api(mapping_key=OVERRIDES[rule.name], mapping_list="default")
        elif rule.name in RESERVES.keys():
            self._logger.debug(f"[yellow]Using reserve {RESERVES[rule.name]} for rule '{rule.name}'")
            scw_data = get_info_from_scw_api(mapping_key=RESERVES[rule.name], mapping_list="default")
        else:
            scw_data = get_info_from_scw_api(mapping_key=rule.cwe_number, mapping_list="cwe")

        try: 
            return ScwInfo(
                contrast_rule_name = rule.name,
                cwe_number = rule.cwe_number,
                url = scw_data['url'],
                name = scw_data['name'],
                description = scw_data['description'],
                video_links = scw_data['videos'],
                links = scw_data['links'],
            )
        except KeyError as e: 
            if scw_data.get("name") == "Not Found": 
                self._logger.debug(f"No SCW info for CWE '{rule.cwe_number}'")
                raise NoSCWInfoException(f"No SCW Information for CWE {rule.cwe_number} - {rule.name})")

        except Exception as e:
            print(f"EXCEPTION trying to get SCW info for rule")
            print(e)
            raise
        
    def get_additional_refs_for_rule(self, rule: Rule):
        self._logger.debug(f"Getting additional refs for rule {rule.name}")
        scw_data = self._get_integration_data(rule)
        refs = scw_data.links

        lang_agnostic_refs = []
        for ref in refs: 
            if ref['languageFrameworks'] == [] and ref['url'] not in REF_EXCLUSIONS and ref['url'] != rule.owasp_link:
                # Contrast can only render the URL here, so there's no point adding any more than that right now
                lang_agnostic_refs.append(ref['url'])
        self._logger.debug(f"Found {len(lang_agnostic_refs)} lang-agnostic refs for rule {rule.name}")
        return lang_agnostic_refs


# Override the mapping from CWE to SCW mapping if a better option exists
OVERRIDES = {
    # "prompt-injection": "InjectionFlaws:ResourceInjection",
}

# Add any SCW references that are not already in the CWE mapping
# Maps CWE numbers to the SCW default MappingKey
RESERVES = {
    "unvalidated-forward": "UnvalidatedRedirectsandForwards:UnvalidatedRedirectsandForwards",
    "session-regenerate": "ImproperSessionHandling:ImproperTimeoutOfSessionID", 
    "hql-injection": "InjectionFlaws:SQLInjection",
    "insecure-jsp-access": "SecurityMisconfiguration:InformationExposure",
    "overly-permissive-cross-domain-policy": "SecurityMisconfiguration:DisabledSecurityFeatures",
    "clickjacking-control-missing": "SecurityMisconfiguration:Clickjacking", 
    "parameter-pollution": "BusinessLogic:InsufficientValidation",
    "reflection-injection": "InjectionFlaws:CodeInjection",
    "redos": "DenialofService:RegularExpressionDoS",
    "viewstate-mac-disabled": "SecurityMisconfiguration:DisabledSecurityFeatures", 
    "csp-header-missing": "SecurityMisconfiguration:DisabledSecurityFeatures", 
    "csp-header-insecure": "SecurityMisconfiguration:DisabledSecurityFeatures", 
    "request-validation-disabled": "SecurityMisconfiguration:DisabledSecurityFeatures", 
    "request-validation-control-disabled": "SecurityMisconfiguration:DisabledSecurityFeatures", 
    "event-validation-disabled": "SecurityMisconfiguration:DisabledSecurityFeatures", 
    "xcontenttype-header-missing": "SecurityMisconfiguration:DisabledSecurityFeatures", 
    "session-rewriting": "SessionHandling:ExposedSessionTokens", 
    "trace-enabled": "InformationExposure:ErrorDetails", 
    "trace-enabled-aspx": "InformationExposure:ErrorDetails", 
    "trust-boundary-violation": "BusinessLogic:LogicalError", 
    "plaintext-conn-strings": "InsecureAuthentication:HardcodedAPIKeys", 
    "unsafe-code-execution": "InjectionFlaws:CodeInjection", 
    "verb-tampering": "SecurityMisconfiguration:DisabledSecurityFeatures", 
    "wcf-metadata-enabled": "SecurityMisconfiguration:InformationExposure", 
}


# SCW TEMPLATE

template = """
{% raw %}{{#header}}Secure Code Warrior {{#omitted}} Integration{{/omitted}}{{/header}}
{{#paragraph}}Learn more about {{#focus}}{% endraw %}{{ policy_info.title }}{% raw %}{{/focus}} vulnerabilities over on the Secure Code Warrior platform by watching videos and completing training exercises and missions that focus on secure coding.{{/paragraph}}{% endraw %}
{% if integration_info.url %}{% raw %}
{{#unorderedList}}
    {{#listElement}}
        {{#linkExternal}}{% endraw %}{{ integration_info.url }}{% raw %}$$LINK_DELIM$$Secure Code Warrior: {% endraw %}{{ policy_info.title }}{% raw %} Training{{/linkExternal}}
    {{/listElement}}{% endraw %}
{% endif %}
{% if integration_info.video_links %}{% raw %}
            {{#listElement}}
                {{#linkExternal}}{% endraw %}{{ integration_info.video_links[0] }}$$LINK_DELIM$$Secure Code Warrior: {{ policy_info.title }} Video{% raw %}{{/linkExternal}}
            {{/listElement}}{% endraw %}
{% endif %}
{% raw %}{{/unorderedList}}{% endraw %}
{% if integration_info.name and integration_info.description %}{% raw %}
        {{#blockQuote}}
            {{#grayedData}}
                {{#focus}}{% endraw %}{{ integration_info.name }}{% raw %}{{/focus}}{{{nl}}}
                {% endraw %}{{ integration_info.description }}{% raw %}
            {{/grayedData}}
        {{/blockQuote}}{% endraw %}
{% endif %}
"""



# EXTRA
REF_EXCLUSIONS = [
    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
    "https://owasp.org/www-community/attacks/Command_Injection",
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    "https://owasp.org/www-community/attacks/Code_Injection",
    "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization",
    "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
    "https://owasp.org/www-community/attacks/XPATH_Injection",
]
