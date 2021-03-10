# Class for interacting with the Contrast TeamServer REST APIs
# Author: josh.anderson@contrastsecurity.com

from collections import defaultdict
import datetime
import json
import re
from urllib.request import Request, urlopen


def load_config():
    with open('config.json', 'r') as config:
        config = json.load(config)

    return config


def contrast_instance_from_json(json):
    return ContrastTeamServer(json['teamserverUrl'], json['apiKey'], json['authorizationHeader'])


class ContrastTeamServer:

    def __init__(self, teamserver_url, api_key, authorization_header, application_metadata_field_name=None):
        teamserver_url = teamserver_url.strip()

        regexBaseUrl = '^(http|https):\/\/[a-z0-9]*([.]|[:])*(contrastsecurity[.]com|[0-9]*)'

        if re.match(regexBaseUrl, teamserver_url):
            if re.match(regexBaseUrl + '$', teamserver_url):
                teamserver_url = teamserver_url + '/Contrast/api/ng/'
            elif re.match(regexBaseUrl + '\/$', teamserver_url):
                teamserver_url = teamserver_url + 'Contrast/api/ng/'
            elif re.match(regexBaseUrl + '\/Contrast$', teamserver_url):
                teamserver_url = teamserver_url + '/api/ng/'
            elif re.match(regexBaseUrl + '\/Contrast\/$', teamserver_url):
                teamserver_url = teamserver_url + 'api/ng/'
            elif re.match(regexBaseUrl + '\/Contrast\/api$', teamserver_url):
                teamserver_url = teamserver_url + '/ng/'
            elif re.match(regexBaseUrl + '\/Contrast\/api\/$', teamserver_url):
                teamserver_url = teamserver_url + 'ng/'
            elif re.match(regexBaseUrl + '\/Contrast\/api\/ng$', teamserver_url):
                teamserver_url = teamserver_url + '/'
            elif re.match(regexBaseUrl + '\/Contrast\/api\/ng\/$', teamserver_url) == None:
                raise ValueError('Unrecognised TeamServer URL')

        self._teamserver_url = teamserver_url
        self._api_key = api_key
        self._authorization_header = authorization_header
        self._application_metadata_field_name = application_metadata_field_name

        self._is_superadmin = False

        self._title_cwe_cache = {}

    @property
    def teamserver_url(self):
        return self._teamserver_url

    # Function to call the Contrast TeamServer REST API and retrieve results as JSON
    def api_request(self, path, api_key=None):
        if api_key is None:
            api_key = self._api_key

        req = Request(self._teamserver_url + path)
        req.add_header('Accept', 'application/json')
        req.add_header('Api-Key', api_key)
        req.add_header('Authorization', self._authorization_header)

        res = urlopen(req).read()
        data = json.loads(res.decode('utf-8'))

        return data

    # Function to POST data to the Contrast TeamServer REST API and retrieve results as JSON
    def post_api_request(self, path, data, api_key=None):
        if api_key is None:
            api_key = self._api_key

        req = Request(self._teamserver_url + path, data)
        req.add_header('Content-Type', 'application/json')
        req.add_header('Accept', 'application/json')
        req.add_header('Api-Key', api_key)
        req.add_header('Authorization', self._authorization_header)

        res = urlopen(req).read()
        data = json.loads(res.decode('utf-8'))

        return data

    # Superadmin API call to retrieve the API key for a specific organization
    def org_api_key(self, org_id):
        if self._is_superadmin:
            return self.api_request('superadmin/organizations/' + org_id + '/apiKey')
        else:
            return {'api_key': self._api_key}

    # Organization specific API call to list assess policy (rules)
    def list_org_policy(self, org_id, api_key, expand_apps=False):
        call = org_id + '/rules?expand=skip_links'
        if expand_apps:
            call += ',app_assess_rules'

        return self.api_request(call, api_key)['rules']

    # Organization specific API call to retrieve CWE ID for a trace. Cache results locally by rule name as a speedup.
    def trace_cwe(self, org_id, title, api_key):
        if len(self._title_cwe_cache) == 0:
            policies = self.list_org_policy(org_id, api_key)
            for policy in policies:
                self._title_cwe_cache[policy['title']] = policy['cwe'].split(
                    '/')[-1].replace('.html', '')

        return self._title_cwe_cache[title]

    def update_rule_references(self, org_id, rule_name, references, api_key):
        values = {
            "references": references
        }

        data = json.dumps(values).encode("utf-8")

        response = self.post_api_request(
            org_id + '/rules/' + rule_name, data, api_key)

        return response
