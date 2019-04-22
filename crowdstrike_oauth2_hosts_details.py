#!/usr/bin/env python
__author__ = "fusseil"
__license__ = "GPL"
import requests
import json
import argparse
import ConfigParser
import time
import os
from datetime import datetime, timedelta

help_desc = '''
Perform CS hosts details queries in order to produce a file for a splunk input

Config file must be filled with a stanza specified as --account %PUT_A_NAME_HERE%
[%PUT_A_NAME_HERE%]
cs_falcon_oauth2_cid = %YOUR_CID_HERE%
cs_falcon_oauth2_key = %YOUR_KEY_HERE%
cs_falcon_output_filename = %YOUR_OUT_FILENAME_HERE%
'''


# import logging
def enable_http_debug():
    """JUST TO GET MORE HTTP DEBUG call me somewhere"""
    try:
        import http.client as http_client
    except ImportError:
        import httplib as http_client
    http_client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


def falcon_init_config(account):
    """Read configuration file to get oauth2 cedentials"""
    config = ConfigParser.RawConfigParser()
    try:
        config.read(config_file)
        cs_falcon_oauth2_cid = str(config.get(account, 'cs_falcon_oauth2_cid'))
        cs_falcon_oauth2_key = str(config.get(account, 'cs_falcon_oauth2_key'))
        cs_falcon_output_filename = str(config.get(account, 'cs_falcon_output_filename'))
    except Exception as e:
        print "Check your config file {0} for section [{1}] and rerun the program, exiting...".format(config_file, account)
        exit(1)
    return (cs_falcon_oauth2_cid, cs_falcon_oauth2_key, cs_falcon_output_filename)


def cs_api_request(method, url, headers=None, params=None, data=None, json_data=None):
    """Method to handle resquests to CrowdStrike APIs"""
    cs_falcon_tempo = 0.08
    response, return_value = None, None
    json_header = {"Content-Type": "application/json"}
    headers = json_header if headers is None else headers
    SUPPORTED_METHODS = ['GET', 'POST']
    if method not in SUPPORTED_METHODS:
        print "{0} method is not a supported".format(method)
        exit(1)
    try:
        if args.debug:
            print "API Request. method: {0} url: {1}".format(method, url)
            print "             headers: {0} data: {1} params: {2}".format(headers, data, params)
        if method == 'GET':
            response = requests.get(url, headers=headers, params=params)
        elif method == 'POST':
            response = requests.post(url, headers=headers, params=params, data=data, json=json_data)
        response.raise_for_status()
        return_value = response.json()
        if args.debug: print "Request successful"
    except requests.exceptions.Timeout:
        print "API request timed out"
        exit(1)
    except requests.exceptions.TooManyRedirects:
        print "API Too Many Redirects"
        exit(1)
    except requests.exceptions.RequestException as err:
        print err
        exit(1)
    except requests.exceptions.HTTPError as err:
        if err.response.content:
            response_content = response.json()
            response_errors = response_content.get('errors')
            response_error_code = response_errors[0].get('code')
            if response_errors and len(response_errors) > 0 and response_error_code in (403, 409, 404):
                print "err_code: {0} err_msg: {1}".format(response_error_code, response_errors[0].get('message'))
                exit(1)
        raise ValueError(err)
    # Tempo to protect from a max api rate limit
    time.sleep(cs_falcon_tempo)
    return return_value


def get_oauth2_token():
    """Calls /oauth2/token endpoint and sets CrowdStrikeHelper.oauth2_token to the new token"""
    get_oauth2_token_url = "{0}{1}".format(cs_falcon_oauth2_base_url, "/oauth2/token")
    get_oauth2_headers = {"accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    get_oauth2_token_data = "client_id={0}&client_secret={1}".format(cs_falcon_oauth2_cid, cs_falcon_oauth2_key)
    if args.debug: print "Requesting new oauth2 Token from {0}".format(get_oauth2_token_url)
    get_oauth2_token_response = cs_api_request(
        method='POST',
        url=get_oauth2_token_url,
        data=get_oauth2_token_data,
        headers=get_oauth2_headers)
    if get_oauth2_token_response.get('error'):
        print "Error getting new oauth2 Token from CrowdStrike: {0}".format(get_oauth2_token_response.get("err_msg"))
        exit(1)
    oauth2_token = get_oauth2_token_response.get("access_token")
    if args.debug: print "New oauth2 Token set successfully {0}".format(get_oauth2_token_response)
    return oauth2_token


def revoke_oauth2_token(oauth2_token):
    """Calls /oauth2/revoke endpoint and sets CrowdStrikeHelper.oauth2_token to the new token"""
    revoke_oauth2_token_url = "{0}{1}".format(cs_falcon_oauth2_base_url, "/oauth2/revoke")
    revoke_oauth2_headers = {"accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    revoke_oauth2_token_data = "token={0}".format(oauth2_token)
    if args.debug: print "Requesting revoke of oauth2 Token from {0}".format(revoke_oauth2_token_url)
    revoke_oauth2_token_response = cs_api_request(
        method='POST',
        url=revoke_oauth2_token_url,
        data=revoke_oauth2_token_data,
        headers=revoke_oauth2_headers)
    if revoke_oauth2_token_response.get('error'):
        raise ValueError("Error revoking oauth2 Token from CrowdStrike: {0}".format(revoke_oauth2_token_response.get("err_msg")))
    if args.debug: print "Revoked oauth2 Token successfully {0}".format(revoke_oauth2_token_response)
    return None


def get_device_details(device_id):
    """Get and return the details of ONE given device"""
    if args.debug: print "Getting the device status for device_id {0}".format(device_id)
    get_device_details_url = "{0}{1}".format(cs_falcon_oauth2_base_url, "/devices/entities/devices/v1")
    get_device_details_header = {"Content-Type": "application/json", "authorization": "bearer {0}".format(oauth2_token)}
    get_device_details_payload = {'ids': device_id}
    get_device_details_response = cs_api_request(
        method='GET',
        url=get_device_details_url,
        headers=get_device_details_header,
        params=get_device_details_payload)
    if args.debug: print "Result {0}".format(get_device_details_response)
    device_details = get_device_details_response.get('resources', [])
    if device_details is None:
        print "Could not get device status for device_id {0}".format(device_id)
    else:
        print json.dumps(device_details)


def get_devices_details(list_of_cs_resources, output_file):
    """Save details of all devices from the given list"""
    get_devices_details_url = "{0}{1}".format(cs_falcon_oauth2_base_url, "/devices/entities/devices/v1")
    get_devices_details_header = {"Content-Type": "application/json", "authorization": "bearer {0}".format(oauth2_token)}
    # A good default value here under is to query 100 hosts per request
    resource_batch_size = 100
    resource_count = 0
    resources_total = len(list_of_cs_resources)
    while True:
        if(resource_count == resources_total):
            if args.verbose: print "Result written to file: {0}".format(cs_falcon_output_filename)
            break
        resource_min = resource_count
        resource_max = min(resource_count + resource_batch_size, resources_total)
        resource_batch = list_of_cs_resources[resource_min:resource_max]
        get_devices_details_payload = ""
        for resource_id in resource_batch:
            resource_count += 1
            get_devices_details_payload += "ids={0}&".format(resource_id)
        if args.verbose: print "Resources details retrieved: {0}/{1}".format(resource_count, resources_total)
        # remove last/extra character (&)
        get_devices_details_payload = get_devices_details_payload[:-1]
        get_devices_details_response = cs_api_request(
            method='GET',
            url=get_devices_details_url,
            headers=get_devices_details_header,
            params=get_devices_details_payload)
        if args.debug: print "Result {0}".format(get_devices_details_response)
        for resource_details in get_devices_details_response['resources']:
            if resource_details is not None:
                if args.debug: print json.dumps(resource_details)
                json.dump(resource_details, output_file)
                output_file.write('\n')


def get_device_list():
    """Get the list of devices seen by crowdstrike over the last 2 hours"""
    # Maximum bulk is 5000
    api_limit = 5000
    api_offset = 0
    list_of_cs_resources = []
    date_2h_ago_from_utc = datetime.utcnow() - timedelta(hours=2, minutes=0)
    list_all_devices_seen_payload = {"filter": "last_seen:>='{0}'".format(
                                        date_2h_ago_from_utc.strftime('%Y-%m-%dT%H:%M:%SZ'))}
    list_all_devices_seen_header = {"Content-Type": "application/json", "authorization": "bearer {0}".format(oauth2_token)}
    while True:
        if args.debug: print "Get Device List (limit={0}, offset={1}) with {2}".format(
                                        api_limit, api_offset, list_all_devices_seen_payload)
        list_all_devices_seen_url = "{0}{1}?limit={2}&offset={3}".format(
                                        cs_falcon_oauth2_base_url, "/devices/queries/devices/v1", api_limit, api_offset)
        list_all_devices_seen_response = cs_api_request(
            method='GET',
            url=list_all_devices_seen_url,
            headers=list_all_devices_seen_header,
            params=list_all_devices_seen_payload)
        if args.debug: print "Result {0}".format(list_all_devices_seen_response)
        resource_total = list_all_devices_seen_response.get('meta', {}).get('pagination', {}).get('total', {})
        list_of_cs_resources += list_all_devices_seen_response.get('resources', [])
        if args.debug: print "resource id retrieved: {0}/{1}".format(len(list_of_cs_resources), resource_total)
        if (len(list_of_cs_resources) == resource_total):
            if args.verbose: print "Hosts seen since {0} UTC : {1}".format(date_2h_ago_from_utc, resource_total)
            break
        else:
            api_offset += api_limit
    return list_of_cs_resources


if __name__ == '__main__':
    cs_falcon_oauth2_base_url = 'https://api.crowdstrike.com'
    config_file = "/home/{0}/.config/falcon-search.cfg".format(os.getenv('USER'))
    parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-c', '--config_file', type=str, help="Specify alt config file")
    parser.add_argument('-a', '--account', type=str, help="Account to use aka config stenza", required=True)
    parser.add_argument('-d', '--debug', action='store_true', help="Enable debugging mode. Default: disabled.")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose mode. Default: disabled.")
    args = parser.parse_args()

    if args.config_file: config_file = args.config_file
    (cs_falcon_oauth2_cid, cs_falcon_oauth2_key, cs_falcon_output_filename) = falcon_init_config(args.account)
    oauth2_token = get_oauth2_token()
    # get_device_details('8871401116644474625b4de5fc57c1a5')
    list_of_cs_resources = get_device_list()
    if args.debug: print "Resources: {0}".format(list_of_cs_resources)
    with open(cs_falcon_output_filename, 'w') as output_file:
        get_devices_details(list_of_cs_resources, output_file)
    # oauth2_token = revoke_oauth2_token(oauth2_token)
    exit(0)
