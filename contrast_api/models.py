import json

from dataclasses import dataclass, field
from typing import Dict, List, Union, Optional

from rich import print

from contrast_api.request_handler import RequestHandler, Response


@dataclass
class User:
    enabled: bool
    status: int
    external: bool
    id: str
    user_uid: str
    password_reset: bool
    api_only: bool
    last_name: str
    first_name: str
    status_description: str
    current_user: bool
    org_management: bool
    tsv_enabled: bool
    superadmin_role: Union[bool,None]
    type: str

    # ONLY for /profile NOT FOR /profile/current-user
    email: Optional[str] = None
    api_only_org: Optional[bool] = None
    enabled_org: Optional[bool] = None
    preferences: Optional[Dict] = None
    login: Optional[Dict] = None
    signup: Optional[Dict] = None
    ip_address: Optional[str] = None

    keys: Optional[Dict] = None
    # SOMETIMES NOT RETURNED
    serverless_enabled: Optional[Union[bool,None]] = None
    rasp_enabled: Optional[Union[bool, None]] = None
    organizationMembershipUuids: Optional[List[str]] = None

    @classmethod
    def from_response(cls, response: Response):
        return cls(**response.data.get("user"))
    
    @property
    def is_superadmin(self):
        return True if self.superadmin_role == "SUPERADMIN" else False
    


@dataclass
class Organization:
    organization_uuid: str
    name: str
    timezone: str
    date_format: str
    time_format: str
    creation_time: int
    locale: str
    auto_license_protection: bool
    ossLicense: bool
    auto_license_assessment: bool
    is_superadmin: bool
    server_environments: list
    harmony_enabled: bool
    sast_enabled: bool
    cloudnative_enabled: bool
    user_protection_enabled: bool
    user_access: bool
    api_only: bool
    cvss_scoring_type: str
    protection_enabled: bool
    vulnerability_trends_graph_enabled: bool
    properties: dict

    roles: list = field(default_factory=list)

    @classmethod
    def from_response(cls, response: Response):
    
        if response.data.get("organization"):
            # print("processing single org")
            roles = response.data.get("roles")
            return cls(**response.data.get("organization"), roles=roles)
        if response.data.get("organizations"):
            # print("processing multiple orgs...")
            return [cls(**org) for org in response.data.get("organizations")]



# POLICIES AND RULES
@dataclass
class BaseClass:
    # _requests: RequestHandler
    # _from_org_uuid: str
    # self._logger = logger or 
    pass

@dataclass
class Rule(BaseClass): # Technically a RuleCustomization
    title: str
    name: str
    description: str
    enabled: bool
    enabled_custom: bool
    likelihood: str
    likelihood_custom: bool
    impact: str
    impact_custom: bool
    confidence_level: str
    confidence_level_custom: bool
    recommendation: str
    references: List[str]
    category: str
    owasp: str
    risk: str
    severity: str
    cwe: int
    messages: List[str]  # messages=['Rule customization loaded successfully']
    success: bool  # success=True

    _policy_handler: "PolicyHandler" = field(repr=False)

    @classmethod
    def from_response(cls, response: Response, _policy_handler):
        return cls(**response.data, _policy_handler=_policy_handler)
    
    @property
    def cwe_number(self):
        """Strip the CWE number from the URL."""
        return self.cwe.split('/')[-1].replace('.html', '')
    
    @property
    def has_custom_levels(self):
        """Check if the rule has custom Likelihood, Impact or Confidence levels set."""
        return True if any([self.likelihood_custom, self.impact_custom, self.confidence_level_custom]) else False
    
    @property
    def has_custom_guidance(self):
        """Check if the rule has either custom references or a custom recommendation."""
        return True if any([self.recommendation, self.risk, self.references]) else False
    
    @property
    def has_customizations(self):
        """Check if the rule has any customizations at all. Checks everything."""
        return True if any([self.has_custom_levels, self.has_custom_guidance]) else False
    
    def update(self, new_recommendation=None, new_references: list = [], new_risk=None, 
               new_confidence_level=None, new_impact=None, new_likelihood=None):
        
        # We need to send all existing customizations back to the API when we make our change, 
        # otherwise it will reset the existing values
        # self._logger.debug(f"Updating policy rule {self.name} for integration")
        # print(f"Updating policy rule {self.name} for integration")

        self.confidence_level_custom = new_confidence_level or self.confidence_level_custom
        self.impact_custom = new_impact or self.impact_custom
        self.likelihood_custom = new_likelihood or self.likelihood_custom
        
        if new_risk:
            # New risk text to be added
            # Wrap our new risk text in paragraph tags
            new_risk = "{{#paragraph}}" + new_risk + "{{/paragraph}}"
        else:
            new_risk = ""

        # If there is existing custom guidance, we'll want to append our new values to the existing ones
        if self.risk:
            # Is the existing risk text already wrapped in paragraph tags?
            if not self.risk.startswith("{{#paragraph}}") and not self.risk.endswith("{{/paragraph}}"):
                # Or does it contain paragraph tags? 
                if "{{#paragraph}}" not in self.risk:
                    # If not, lets wrap it now
                    self.risk = "{{#paragraph}}" + self.risk + "{{/paragraph}}"
        else: 
            self.risk = ""

        # Now append the new and existing risk text together as long as it doesn't already exist
        # TODO: This needs work!! 
        if new_risk not in self.risk:      
            self.risk += new_risk

        # Now add the references together 
        # And to be safe, we'll want to remove any duplicates
        self.references = list(dict.fromkeys(self.references + new_references))

        # if recommendation:
            # Because we are now adding a SCW recommendation block, we can just overwrite the existing recommendation
        # TODO: FIX THIS
        # FIXME: FIX THIS
        self.recommendation = new_recommendation

        customizations = {
            "confidence_level": new_confidence_level or self.confidence_level_custom,
            "impact": new_impact or self.impact_custom,
            "likelihood": new_likelihood or self.likelihood_custom,
            "recommendation": new_recommendation or self.recommendation,
            "references": new_references or self.references,
            "risk": new_risk or self.risk,
        }

        response = self._policy_handler.update_rule(rule_name=self.name, customizations=customizations)
        return self


    def reset(self):
        """Reset the current rule back to default values. 
        This will remove all customizations and integrations.
        """

        response = self._policy_handler.reset_rule(self.name)

        # Now set our object attributes to the default values
        self.likelihood_custom = None
        self.impact_custom = None
        self.confidence_level_custom = None
        self.recommendation = ""
        self.references = []
        self.risk = ""
        return self


    
    

    

@dataclass
class Policy:
    count: int
    rules: List[Dict]

    @classmethod
    def from_response(cls, response: Response):
        rule_list = [rule for rule in response.data.get("rules")]
        return cls(response.data.get("count"), response.data.get("rules"))

