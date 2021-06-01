# Script to query Contrast TeamServer to populate the vulnerability references with Secure Code Warrior video links
# Author(s): josh.anderson@contrastsecurity.com / david.archer@contrastsecurity.com

from urllib.request import Request, urlopen
from contrast_api import load_config, contrast_instance_from_json
from contrast_api import ContrastTeamServer
import traceback
import json
import urllib.parse
import sys

config = load_config()
org_id = config['orgId']

contrast = contrast_instance_from_json(config)

is_reset = sys.argv and len(sys.argv) > 1 and sys.argv[1] == 'reset'

allow_product_usage_analytics = config.get('allowProductUsageAnalytics', False)
enable_verbose_error_logging = config.get('enableVerboseErrorLogging', False)


def get_scw_base_url(cwe):
    return 'https://integration-api.securecodewarrior.com/api/v1/trial?Id=contrast&MappingList=cwe&MappingKey=' + cwe


def get_scw_data(url):
    try:
        req = Request(url)

        res = urlopen(req).read()
        data = json.loads(res.decode('utf-8'))

        return data
    except urllib.error.HTTPError as err:
        print(err)


def map_contrast_lang_to_scw_lang(contrast_lang):
    langs = {'.NET': 'c#', '.NET Core': 'c#(.net):mvc', 'Java': 'java',
             'Node': 'nodejs', 'Python': 'python:django', 'Ruby': 'ruby'}  # 'Go': 'go'
    return langs.get(contrast_lang, '')


org_key = contrast.org_api_key(org_id)['api_key']

# Loop through all the Assess rules
for rule in contrast.list_org_policy(org_id, org_key):
    if is_reset:
        #The reset argument has been passed, erase all rule references.
        res = contrast.update_rule_references(
            org_id, rule['name'], [], org_key)

        if res['success'] == True:
            print(rule['title'] + ' reset successfully')
        
    else:
        refs = []
        video = ''

        # Extract the CWE number for this rule
        reserves = {
            'escape-templates-off': 'https://media.securecodewarrior.com/v2/Security_Misconfiguration_v2.mp4',
            'clickjacking-control-missing': 'https://media.securecodewarrior.com/v2/Module_25_CLICKJACKING_v2.mp4',
            'event-validation-disabled': 'https://media.securecodewarrior.com/v2/Security_Misconfiguration_v2.mp4',
            'forms-auth-protection': 'https://media.securecodewarrior.com/v2/Security_Misconfiguration_v2.mp4',
            'forms-auth-redirect': 'https://media.securecodewarrior.com/v2/Security_Misconfiguration_v2.mp4',
            'http-only-disabled': 'https://media.securecodewarrior.com/v2/Module_74_WEAK_SESSION_TOKEN_GENERATION_v2.mp4',
            'httponly': 'https://media.securecodewarrior.com/v2/Module_74_WEAK_SESSION_TOKEN_GENERATION_v2.mp4',
            'max-request-length': 'https://media.securecodewarrior.com/v2/Module_54_DoS_Generic_v2.mp4',
            'rails-http-only-disabled': 'https://media.securecodewarrior.com/v2/Module_74_WEAK_SESSION_TOKEN_GENERATION_v2.mp4',
            'reflected-xss': 'https://media.securecodewarrior.com/v2/Module_73_Reflected_Cross+Site+Scripting_v2.mp4',
            'request-validation-disabled': 'https://media.securecodewarrior.com/v2/Security_Misconfiguration_v2.mp4',
            'request-validation-control-disabled': 'https://media.securecodewarrior.com/v2/Security_Misconfiguration_v2.mp4',
            'role-manager-protection': 'https://media.securecodewarrior.com/v2/Security_Misconfiguration_v2.mp4',
            'session-rewriting': 'https://media.securecodewarrior.com/v2/module_136_exposed_session_tokens.mp4',
            'session-regenerate': 'https://media.securecodewarrior.com/v2/Module_74_WEAK_SESSION_TOKEN_GENERATION_v2.mp4',
            'stored-xss': 'https://media.securecodewarrior.com/v2/Module_72_Stored_Cross+Site+Scripting_v2.mp4',
            'version-header-enabled': 'https://media.securecodewarrior.com/v2/Security_Misconfiguration_v2.mp4',
            'verb-tampering': 'https://media.securecodewarrior.com/v2/Security_Misconfiguration_v2.mp4',
            'viewstate-mac-disabled': 'https://media.securecodewarrior.com/v2/Security_Misconfiguration_v2.mp4',
            'wcf-detect-replays': 'https://media.securecodewarrior.com/v2/Security_Misconfiguration_v2.mp4',
            'wcf-exception-details': 'https://media.securecodewarrior.com/v2/module_184_error_details.mp4',
            'wcf-metadata-enabled': 'https://media.securecodewarrior.com/v2/module_184_error_details.mp4',
            'x-powered-by-header': 'https://media.securecodewarrior.com/v2/module_184_error_details.mp4',
            'xxssprotection-header-disabled': 'https://media.securecodewarrior.com/v2/Module_73_Reflected_Cross+Site+Scripting_v2.mp4'
        }

        cwe = contrast.trace_cwe(org_id, rule['title'], org_key)

        # Compose a url for this training exercise
        scw_url = get_scw_base_url(cwe)

        # Get the data for this exercise from scw
        response = get_scw_data(scw_url)

        # We got a hit
        if response:
            # Do we have a video, if so add it?
            if 'videos' in response and len(response['videos']) > 0:
                file = response['videos'][0].replace(' ', '+')
            else:
                file = reserves.get(rule['name'], '')

            if file != '':
                video = '<br>Watch a video on this topic with Secure Code Warrior (beta):<br>' + file
            else:
                print('Missing video for rule: ' +
                    rule['title'] + ', cwe ' + cwe + ', SCW url: ' + scw_url)

            # Loop through all the languages for this rule
            for lang in rule['languages']:

                # Map the contrast language to a SCW language
                scw_lang = map_contrast_lang_to_scw_lang(lang)

                if scw_lang != '':
                    # Compose the URL for training exercise
                    training_url = scw_url + '&LanguageKey=' + \
                        urllib.parse.quote(lang) + '&redirect=true'

                    # If this is the first language, add some chrome:
                    if len(refs) == 0:
                        ref = '<br>Complete a training exercise on this topic for your language using Secure Code Warrior (beta):<br><b>' + \
                            lang + '</b>: ' + training_url
                    else:
                        ref = '<b>' + lang + '</b>: ' + training_url

                    refs.append(ref)
        else:
            print('No response for rule: ' +
                rule['title'] + ', cwe ' + cwe + ', SCW url: ' + scw_url)

        if video != '':
            refs.insert(0, video)

        if len(refs) > 0:
            # Update the rule references in Contrast
            res = contrast.update_rule_references(
                org_id, rule['name'], refs, org_key)

            if res['success'] == True:
                print(rule['title'] + ' updated successfully')
                

if allow_product_usage_analytics:
    try:
        contrast.send_usage_event(org_id, is_reset, org_key)

    except urllib.error.HTTPError as err:
        if enable_verbose_error_logging:
            print(traceback.format_exc())
        else:
            print("Unable to send usage data")
