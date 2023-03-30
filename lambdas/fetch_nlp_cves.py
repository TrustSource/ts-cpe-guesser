"""
This module provides filtered data from vulnDB.cve_nlp in JSON format as a response
to a simple GET request via API.
"""
import datetime
import json
import dateutil.parser as dateparser
import os
from utils import connect_to_vulndb

NLP_COLLECTION_NAME = "cve_nlp"
ENV = os.environ.get("ENV")


def lambda_handler(event: dict, context) -> dict:
    """
    Args:
        event:
            valid event keys: "API" will do.
            valid values for key "action":
        context:
            unused

    """
    print("Processing Request")

    vulndb = connect_to_vulndb(ENV)

    cves_nlp = vulndb["cve_nlp"].find({})
    cves_nlp = get_modified_within_timeframe(cves_nlp, timeframe=datetime.timedelta(days=210))
    # CVEs with actual CPE matches are redundant
    cves_nlp = [cve for cve in cves_nlp if (cve["cpe_matches"] and cve["cpe_matches_nlp"])]
    payload = format_cves_for_message(cves_nlp)
    print("Returning List of CVEs...")
    try:
        response = {"statusCode": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps(payload)}
    except Exception as E:
        print(E)
        raise E

    return response


def get_modified_within_timeframe(cves: [{}], timeframe: datetime.timedelta):
    """
    Args:
        cves: List of CVEs ({}) from tsvulndb.cve_nlp
        timeframe: Timeframe within which CVEs of interest were added or modified
    Returns:
        cves {}
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    last_accept_date = now - timeframe
    cves = [cve for cve in cves
            if (dateparser.parse(cve["lastmodified"]) > last_accept_date)]
    return cves


def format_cves_for_message(cves_nlp):
    formatted_list = []
    for cve in cves_nlp:
        entry = {"cve_id": cve["cve_id"], "description": cve["description"]}

        # Regular Match
        match = cve["cpe_matches"][0]
        match["vendor"] = match["cpe23Uri"].split(":")[3]
        match["product"] = match["cpe23Uri"].split(":")[4]
        match["version"] = match["cpe23Uri"].split(":")[5]
        entry["cpe_match"] = match

        # NLP MATCH
        match = cve["cpe_matches_nlp"][0]
        del match["nlp_method"]
        match["vendor"] = match["cpe_uri"].split(":")[3]
        match["product"] = match["cpe_uri"].split(":")[4]
        match["version"] = match["cpe_uri"].split(":")[5]
        entry["cpe_match_nlp"] = match

        entry["last_modified"] = cve["lastmodified"]

        formatted_list.append(entry)

    cves_json = {"cves_nlp": formatted_list}
    return cves_json



