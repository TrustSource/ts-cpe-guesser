import os
import datetime
import json
import boto3
import re
import requests
import pathlib

from ts_vulndb.data import Database
from botocore.exceptions import ClientError


def get_credentials(secret_name = "trustsource/mongo/vulndb"):
    """retrieves db connection string form secrets manager"""
    # Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
    #
    # This file is licensed under the Apache License, Version 2.0 (the "License").
    # You may not use this file except in compliance with the License. A copy of the
    # License is located at
    #
    # http://aws.amazon.com/apache2.0/

    region_name = "eu-central-1"
    secret = ''
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager', region_name=region_name)
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        print('Unhandled error: {0}'.format(e.response['Error']['Code']))
        if e.response['Error']['Code'] == 'AuthenticationError':
            # Secrets Manager or secret were not accessible.
            print('Authentication error while accessing secrets: Verify access rights and policies')
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            print('Can not decrypt')
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            print('Can not decrypt')
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        if get_secret_value_response.get('SecretString'):
            # some tricky misuse of json.loads to get a dict as result
            mydic = json.loads(get_secret_value_response['SecretString'])
            # pick the secret string only
            secret = mydic['uri']

    return secret


def connect_to_vulndb(env: str = "aws") -> Database:
    """

    Args:
        env: string name for the environment where the database is located. ("aws"|"local"|"docker")

    Returns:
        vulndb: TrustSource Database of vulnerabilities from various sources.
    """
    try:
        if env == "aws":
            print("Acquiring database credentials ..")
            vulndb_uri = get_credentials()
            assert len(vulndb_uri) > 0
        elif env == "local":
            vulndb_uri = "localhost"
        elif env == "docker":
            vulndb_uri = "host.docker.internal"
        else:
            raise ValueError(f"Invalid value for 'env': {env}. Must be one of ['aws','local','docker']")
    except AssertionError as e:
        print("Failed to acquire credentials: ")
        raise e

    try:
        print("Connecting to database .. ")
        vulndb = Database.open(vulndb_uri, name="vulnDB")
        print("Success")
    except Exception as e:
        print("Failed to open Database: ")
        raise e
    return vulndb


ADAPTIVE_CARD_ITEM = {'text': '**PROVIDEHERETHECVEID**',
                      'type': 'TextBlock'}
ADAPTIVE_CARD_ITEM_SUBTLE = {'isSubtle': True,
                             'spacing': 'small',
                             'text': 'date:12/12/2017',
                             'type': 'TextBlock'}


def broadcast_to_teams(nlp_cves: {}, multi_message: bool = False):
    """

    Args:
        nlp_cve: A CVE Item (dict) or list of CVE Items.
        multi_message: If true, all CVE items are broadcast via individual messages

    Returns:

    """
    if nlp_cves is isinstance(nlp_cves, list) and multi_message:
        for cve in nlp_cves:
            broadcast_to_teams(cve)

    teams_webhook = open(pathlib.Path("./teams_webhook.txt")).read()
    card_template = json.load(open(pathlib.Path("./teams_card_template.json"))).copy()

    card_template["title"] = f"Generated CPE using NLP"
    card_template["sections"][0]["activitySubtitle"] = datetime.datetime.now().strftime("%Y-%m-%d, %T")

    sections = create_card_sections(nlp_cves)
    card_template["sections"] += sections

    card_template = json.dumps(card_template)
    #print(card_template)
    answer = requests.post(teams_webhook, data=card_template, headers={"Content-Type": "application/json"})
    print(f"Posted Template to Teams. Response code: {answer.status_code}, Reason: {answer.text}")
    return answer


def create_card_sections(nlp_cves):
    if not isinstance(nlp_cves, list):
        nlp_cves = [nlp_cves]

    sections = []
    for nlp_cve in nlp_cves:
        card_cve_item = {'name': "CVE ID:",
                         'value': f'**{nlp_cve["cve_id"]}**'}

        card_descr_item = {'name': "Description",
                           'value': nlp_cve["description"]}

        cpe_match = nlp_cve["cpe_matches_nlp"][0]
        if "nlp_method" in cpe_match.keys():
            del cpe_match["nlp_method"]
        for key in cpe_match.keys():
            cpe_match[key] = re.sub(r"\*", "\\*", cpe_match[key])
        cpe_match_str = "  \n".join([f"**{key}**:   {cpe_match[key]}" for key in cpe_match.keys()])
        card_cpe_item = {'name': "Generated CPE Match:",
                         'value': cpe_match_str}

        section = {"facts": [card_cve_item, card_descr_item, card_cpe_item]}
        sections.append(section)

    return sections


def post_to_teams_test():
    db = connect_to_vulndb("local")
    mock_cve = db["cve_nlp"].find_one()
    mock_cve["cve_id"] = "CVE-MOCK-ID"
    mock_cve["lastmodified"] = '2022-09-16T03:15Z'
    mock_cve2 = mock_cve.copy()
    mock_cve2["cve_id"]= "CVE-MOCK-ID-2"
    response = broadcast_to_teams([mock_cve, mock_cve2], multi_message=False)

