import json
import requests

from rich import print

from contrast_api.models import *
from contrast_api.request_handler import RequestHandler

class BaseAPI:
    api_version = "api/ng"

    def __init__(self, session, api_config):
        self._session = session
        self._config = api_config

        self.hostname = self._config.teamserver_url
        self.requests = RequestHandler(session=self._session)

    @property
    def _base_url(self) -> str:
        base_url = self.hostname 
        base_url += f"/{self.api_version}" if self.api_version else ""
        return base_url
    
    @property
    def current_org_uuid(self):
        if self._config.active_profile:
            return self._config.active_profile.org_uuid
        else:
            return self._config.default_profile.org_uuid
    
    def full_url(self, endpoint: str) -> str:
        return f"{self._base_url}/{endpoint}"
    
    def get(self, endpoint: str, skip_links: bool = False, expand: str = None, params: Dict = None) -> Response:
        if any([skip_links, expand, params]):
            params = params or {}
            expand = expand or ""
            if skip_links:
                expand = "skip_links," + expand
            if expand: 
                params["expand"] = expand
        return self.requests.get(url=self.full_url(endpoint), params=params)

    def post(self, endpoint: str, skip_links: bool = False, expand: List = None, params: Dict = None, data: Dict = {}) -> Response:
        if any([skip_links, expand, params]):
            params = params or {}
            expand = expand or ""
            if skip_links:
                expand = "skip_links," + expand
            if expand: 
                params["expand"] = expand
        return self.requests.post(url=self.full_url(endpoint), params=params, data=data)


class APIHandler(BaseAPI):
    api_version = ""

    def get_current_user_profile(self):
        print("Getting current user profile")
        return self.get("profile/current-user")


class PolicyHandler(BaseAPI):

    def get_org_policy(self) -> Policy:
        response = self.get(f"{self.current_org_uuid}/rules", skip_links=True)
        return Policy.from_response(response)
    
    def get_details_for_rule(self, rule_name: str) -> Rule:
        response = self.get(f"{self.current_org_uuid}/rules/{rule_name}")
        return Rule.from_response(response, _policy_handler=self)
    
    def reset_rule(self, rule_name: str) -> Response:
        response = self.post(f"{self.current_org_uuid}/rules/{rule_name}", data={"override": "false"})
        return response
    
    def update_rule(self, rule_name: str, customizations: Dict) -> Response:
        response = self.post(f"{self.current_org_uuid}/rules/{rule_name}", data=customizations)
        return response


class ProfileHandler(BaseAPI):

    def get_profile(self):
        response = self.get("profile", expand="email,preferences,login,signup,service_key,ip_address")
        return User.from_response(response)

    def get_current_user_profile(self):
        response = self.get("profile/current-user", expand="ip_address")
        return User.from_response(response)

    def get_organizations_in_profile(self):
        response = self.get("profile/organizations", expand="role")
        return Organization.from_response(response)
    
    def get_default_org_from_profile(self):
        response = self.get("profile/organizations/default")
        return Organization.from_response(response)
    
    def get_profile_user_roles_for_org(self):
        response = self.get(f"profile/organizations/{self.current_org_uuid}", expand="role")
        return Organization.from_response(response)
