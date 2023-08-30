"""Provides a framework for adding integrations to contrast via Contrast Policy Rule customizations.
    1. Add rich content to a Rule 
        a. In the Risk text
        b. In the Remediation text
        c. In the References section
"""

# Import all existing integration block types here

import re

from rich import print
from rich.console import Console
from rich.logging import RichHandler

import logging
# logging.basicConfig(level="INFO", datefmt="[%X]", format="%(name)s: %(message)s", handlers=[RichHandler(markup=True)])
logger = logging.getLogger(__name__)

def parse_existing_integration_blocks(existing_recommendation, integration_header, integration_footer):
    """Parse a custom recommendation for the existence of an integration block."""
    
    # Remove whitespace that Contrast adds to recommendations
    existing_recommendation = existing_recommendation.replace("\n", " ").strip()

    blocks = None
    if integration_header in existing_recommendation and integration_footer in existing_recommendation:

        pattern = re.compile(f"{integration_header}(.+?){integration_footer}", re.DOTALL)
        matches = pattern.finditer(existing_recommendation)

        blocks = []
        for match in matches:
            integration_block = match.group()
            blocks.append(integration_block)
        
    return blocks

def parse_existing_recommendation(existing_recommendation):
    integrations = [
        'SCW',
        'SecureFlag',
    ]
    integration_blocks = {}
    remaining_recommendation = existing_recommendation.replace("\n", " ").strip()
    for integration_type in integrations:
        integration_header = "{{!-- begin " + integration_type + " integration block --}}"
        integration_footer = "{{!-- end " + integration_type + " integration block --}}"
        blocks = parse_existing_integration_blocks(existing_recommendation, integration_header, integration_footer)

        if blocks:
            for block in blocks:
                integration_content = block
                integration_blocks[integration_type] = integration_content
                remaining_recommendation = remaining_recommendation.replace(integration_content, "").strip()
    
    if remaining_recommendation:
        integration_blocks["OTHER"] = remaining_recommendation

    return integration_blocks


import jinja2

class Integration:
    def __init__(self, name, template): 
        self.name = name
        self._template = template
        self._logger = logger or logging.getLogger(__name__)

    @property
    def integration_block_header(self):
        return "{{!-- begin " + self.name + " integration block --}}"
    
    @property
    def integration_block_footer(self):
        return "{{!-- end " + self.name + " integration block --}}"
    
    @property
    def template(self):
        # Add the header and footer to the main template with raw tags
        header = "{% raw %}" + self.integration_block_header + "{% endraw %}"
        footer = "{% raw %}" + self.integration_block_footer + "{% endraw %}"
        return header + self._template + footer

    def _render_block(self, integration_data, policy_rule):
        self._logger.debug(f"Rendering template for block {policy_rule.name}")
        environment = jinja2.Environment()
        hb_template = environment.from_string(self.template)
        render = hb_template.render(integration_info=integration_data, policy_info=policy_rule)
        integration_block = render.replace("\n", " ").strip()
        self._logger.debug(f"Rendered block: {integration_block}")
        return integration_block

    def _parse_existing_block(self, existing_recommendation):
        self._logger.debug(f"Parsing existing recommendation for integration blocks.")
        parsed_blocks = parse_existing_recommendation(existing_recommendation)
        self._logger.debug(f"Parsed blocks: {parsed_blocks}")

        non_integration_recommendation = ""
        if 'OTHER' in parsed_blocks:
            self._logger.debug("Found non-integration content in recommendation.")
            non_integration_recommendation = parsed_blocks['OTHER']
            if not non_integration_recommendation.startswith("{{#paragraph}}") and not non_integration_recommendation.endswith("{{/paragraph}}"):
                if "{{#paragraph}}" not in non_integration_recommendation:
                    non_integration_recommendation = "{{#paragraph}}" + non_integration_recommendation + "{{/paragraph}}"

        integration_blocks = ""
        for integration_name, content in parsed_blocks.items():
            self._logger.debug(f"Found existing integration block for {integration_name}. Adding this back in")
            if integration_name != "OTHER" and integration_name != self.name:
                integration_blocks += content
                self._logger.debug(integration_blocks)

        parsed_recommendation = non_integration_recommendation + integration_blocks
        self._logger.debug(f"Parsed recommendation: {parsed_recommendation}")
        return parsed_recommendation
    
    def _get_integration_data(self, policy_rule):
        pass
    
    def add_integration_block(self, policy_rule): 
        """Add an integration block to an existing recommendation."""
        self._logger.debug(f"Adding integration block to {policy_rule.name}.")
        integration_data = self._get_integration_data(policy_rule)
        if policy_rule.recommendation:
            parsed_recommendation = self._parse_existing_block(policy_rule.recommendation)
        else: 
            parsed_recommendation = ""
        integration_block = self._render_block(integration_data, policy_rule)
        new_recommendation = parsed_recommendation + integration_block
        self._logger.debug(new_recommendation)
        self._logger.debug(f"Updating {policy_rule.name} with new recommendation.")
        result = policy_rule.update(new_recommendation)
        return result
    
    def remove_integration_block(self, policy_rule): 
        """Add an integration block to an existing recommendation."""
        self._logger.debug(f"Removing integration block from {policy_rule.name}.")
        if policy_rule.recommendation:
            self._logger.debug(f"Found existing recommendation for {policy_rule.name}.")
            parsed_recommendation = self._parse_existing_block(policy_rule.recommendation)
        else: 
            parsed_recommendation = ""
        self._logger.debug(f"parsed_recommendation: {parsed_recommendation}")
        result = policy_rule.update(parsed_recommendation)

        return result

