# Secure Code Warrior Integration (beta)

This script is used to provide links from within Contrast to relevant training videos and exercises within the Secure Code Warrior platform. The links appear in the "How to Fix" area of a vulnerability within the Contrast TeamServer API and IDE plugins.

It should not be confused with the SCW Jira plugin which is created and managed by the SCW team.

The script performs the following logic:

```
Extract a list of rules from the Contrast organisation
    For each rule
        Call the SCW API using the CWE code
        
        If a video exists
            Grab the video URL for this CWE
        Otherwise
            If we have an reserve set up for this rule
                Grab the reserve video URL for this CWE

        For each language
            Create an integration URL for SCW
        Next

        Call the Contrast API to update the references for this rule with the videos and training links
    Next
```

## Requirements

This script requires Python3 and organizational admin privileges to run.

## Setup

Steps:
1. Login to the Contrast TeamServer in your browser
1. Click your name in the top right, and select 'Your Account'.
1. Update the config.json with details about your TeamServer and credentials from the 'Your Keys' section. If EOP, please ensure the url ends in `/api/ng/`.

## Recommendations

Contrast only supports one set of references per rule. Consider modifying the languages map in the `map_contrast_lang_to_scw_lang` function within [contrast_scw.py](contrast_scw.py) function to suit your customer's most popular frameworks in order they receive the most relevant training material. For a list of supported languages run: 

```curl -X GET "https://integration-api.securecodewarrior.com/api/v1/language-keys" -H "accept: text/plain"```

## ** WARNING **

This script will overwrite any manual rule references that you may have added to your Contrast environment in Policy Management > Assess Rules.

## Running the Script

Run with `python3 contrast_scw.py`. It can be run more than once should changes be made to the script, it will overwrite the rule references each time it is run.

## Resetting the rules

Run with an additional parameter `python3 contrast_scw.py reset` to reset your Contrast rules. This will remove all the SCW links and any manual rule references that you may have added.

## Tested on

* SaaS and EOP environments with TeamServer version 3.7.11
* Python version 3.7

## Known Issues / Limitations

* The reserve rules (used when a CWE video could not be found using the API) have hardcoded SCW URLs which might change in the future.
* The Contrast IDE plugins do not yet render clickable links.
* The Contrast IDE plugins do not yet render html content so this markup is visible within the IDE plugin.
* Not every rule has a SCW video available.

## Terms and Conditions
By installing this integration, you agree to the [Contrast Beta Terms and Conditions](https://docs.contrastsecurity.com/en/beta-terms-and-conditions.html).
