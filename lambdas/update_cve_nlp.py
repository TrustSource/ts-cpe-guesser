"""
Some newly assigned or modified CVEs don't have CPE assignments.
This module uses Natural-Language-Processing (NLP) methods to infer a CPE assignment for these CVEs
based on their description. These CVEs are stored in "cve_nlp" together with their inferred CPE assignments.
Furthermore, NLP assignments are broadcast to an internal channel (microsoft teams) and artificially
assigned CVEs are broadcast to an SNS Topic ("updateCveNlp").
CVEs are fetched from the 'nvd-modified' feed. CVEs in this feed have been added or modified within
the last 8 days.
"""
import datetime
import json
from typing import Union

import boto3
import dateutil.parser as dateparser
import traceback
import os

from utils import connect_to_vulndb
from utils import broadcast_to_teams
from ts_vulndb import nlp
from ts_vulndb import vulns
from ts_vulndb.data import Database
from ts_vulndb.sources import nvd
from ts_vulndb.sources.model import nvd as nvd_model

NLP_COLLECTION_NAME = "cve_nlp"
ENV = os.environ.get("ENV")
H = int(os.environ.get("ACCEPTABLE_HOURS", ""))
TOPIC = os.environ.get("CVE_NLP_UPDATES_TOPIC", "")


def lambda_handler(event: dict, context) -> dict:
    """
    Fetches new NVD CVEs. Looks for unassigned CVEs. Generates CPE assignments for them,
    using NLP. Uploads these CVEs to vulnDB.cve_nlp.

    Args:
        event:
            valid event keys: ["action"],
            valid values for key "action": ["update","drop_collection"]
        context:
            unused
    Returns:
        response:
                response dict with "status" and "body".
                Response body: "Success", Error Raised otherwise
    """
    global H
    print("Received an event: ")
    print(event)
    if type(event) == str:  # weird API Calls might send JSON as str
        print(type(event))
        event = json.loads(event)

    if "action" not in event.keys():
        raise KeyError("Missing 'action' key.")
    if event["action"] not in ["update", "test", "drop_collection"]:
        raise ValueError(f"Unrecognized 'action': {event['action']}")
    if "hours" in event.keys():
        H = int(event["hours"])

    # Make sure we can connect to DB first. Otherwise, the following operations are a waste of resources.
    vulndb = connect_to_vulndb(ENV)
    if event["action"] == "drop_collection":
        vulndb[NLP_COLLECTION_NAME].drop
        return {"status": 200, "body": f"Dropped Collection {NLP_COLLECTION_NAME}"}

    # Making sure cve_ids are index values for quicker searches.
    if "cve_id" not in vulndb[NLP_COLLECTION_NAME].index_information().keys():
        vulndb[NLP_COLLECTION_NAME].create_index("cve_id")

    nvdmodified = nvd.fetch_modified(model=True)
    print(f"\tTotal: {len(nvdmodified.cve_items)}")

    print(f"Selecting those that were updated within the last {H} hours..")
    relevant_cves = get_modified_within_timeframe(nvdmodified.cve_items, hours=H)
    if not relevant_cves:
        print("No CVEs were modified within the selected time frame.")
        return {"status": 200, "body": "No CVEs modified within time frame."}
    print(f"\tModified within selected timeframe: {len(relevant_cves)}")

    # UNASSIGNED CVES #
    print("Among these, filtering for those without CPE assignment or explicitly affected products..")
    unassigned_cves = get_unassigned_cves(relevant_cves)
    print(f"\tNumber of unassigned CVEs: {len(unassigned_cves)}")
    if unassigned_cves:
        print(f"Using NLP to generate CPE matches from descriptions..")
        nlp_assigned_cves = assign_nlp_matches(unassigned_cves)
        print(f"Uploading CVEs to {NLP_COLLECTION_NAME}..")
        upload_nlp_cves(cve_items=nlp_assigned_cves, db=vulndb,
                        collection_name=NLP_COLLECTION_NAME)
        try:
            print("Building vulns and uploading them to 'vulns_nlp'..")
            vulns_to_add = vulns_from_nlp_cves(nlp_assigned_cves)
            nvd.upload_vulns(vulns_to_add, vulndb, collection="vulns_nlp", merge=True)
        except Exception:
            print(f"Failed to upload_vulns:")
            traceback.print_exc()
        try:
            print("Posting NLP assignments to internal Teams Channel")
            broadcast_to_teams(nlp_assigned_cves, multi_message=True)
        except Exception:
            print(f"Failed to broadcast NLP CVEs to Teams Channel:")
            traceback.print_exc()

    ## ASSIGNED CVES ##
    print("Getting assigned CVEs and finding outdated NLP generated CPEs in DB..")
    assigned_cves = get_assigned_cves(relevant_cves)
    if assigned_cves:
        outdated_cves = handle_newly_assigned_cves(assigned_cves, vulndb, NLP_COLLECTION_NAME)
        print(f"{len(outdated_cves)} NLP generated CPE assignments will be replaced by expert assignments.")
        try:
            print("Taking care of outdated CVEs in vunls_nlp..")
            remove_cves_from_vulns(outdated_cves, vulndb, "vulns_nlp")
        except Exception as E:
            print(f"Failed to remove CVEs from vulns: {E}")
    # broadcast_cve_nlp_updates(vulns_to_add, vulns_to_delete)

    return {"status": 200, "body": "Success"}


def get_modified_within_timeframe(cves: [nvd_model.DefCveItemClass], hours: int):
    """
    Args:
        cves: List of CVEs (DefCveItemClass) from ts_vulndb.sources.model.nvd
        hours: Timeframe within which CVEs of interest were added or modified
    Returns:
        cves ([DefCveItemClass]):
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    last_fetch_date = now - datetime.timedelta(hours=hours)
    cves = [cve for cve in cves
            if (dateparser.parse(cve.last_modified_date) > last_fetch_date) or
            (dateparser.parse(cve.published_date) > last_fetch_date)]
    return cves


def get_assigned_cves(cves: [nvd_model.DefCveItemClass]):
    """
    Returns a list of CVE items with cpe_matches
    """
    cves = [format_cve_for_db(cve) for cve in cves
            if has_cpe_matches(cve)]
    return cves


def get_unassigned_cves(cves: [nvd_model.DefCveItemClass]):
    """
    Returns a list of CVE items without cpe_matches
    """
    cves = [format_cve_for_db(cve) for cve in cves
            if not has_cpe_matches(cve)]
    cves = [cve for cve in cves if not cve["affected"]]
    return cves


def has_cpe_matches(cve: nvd_model.DefCveItemClass):
    if isinstance(cve, dict):
        cve = nvd_model.DefCveItemClass.from_dict(cve)

    if not cve.configurations.nodes:
        return False

    for node in cve.configurations.nodes:
        if _has_cpe_uri(node):
            return True


def _has_cpe_uri(node: nvd_model.DefNodeClass) -> bool:
    """

    Args:
        node: Two Attributes - children :: [DefNodeClass], cpe_match :: [DefCpeMatch]
    Returns:
        True if a non-empty cpe22_uri or cpe23_uri string is found in any node or child node
    """
    if node.cpe_match:
        for match in node.cpe_match:
            if match.cpe22_uri or match.cpe23_uri:
                return True

    elif node.children:
        for child_node in node.children:
            if _has_cpe_uri(child_node):
                return True
    else:
        return False


def strip_nlp_match_keys(nlp_match: dict) -> dict:
    """
    Only leaves the keys "cpe_uri","version" and [versionLimits] to
    match the original cpe_matches in nvd sources.
    """
    for key in ["vendor", "product", "description", "version"]:
        if key in nlp_match.keys():
            del nlp_match[key]
    return nlp_match


def assign_nlp_matches(cves: [Union[nvd_model.DefCveItemClass, dict]]) -> [{}]:
    """
    Creates nlp matches from CVE descriptions, and adds these
    assignments to a new field "cpe_matches_nlp" for each CVE.
    Has to be done in bulk due to how generate_cpe_matches works.
    Args:
        cves: List of CVEs obtained from `format_cve_for_db` or DefCveItemClass
    Returns:

    """
    if not cves:
        return []
    if isinstance(cves[0], nvd_model.DefCveItemClass):
        cves = [format_cve_for_db(cve) for cve in cves]

    descriptions = [cve["description"] for cve in cves]
    nlp_matches = nlp.generate_cpe_matches(descriptions, verbose=False)
    for cve, nlp_match in zip(cves, nlp_matches):
        # Only keep the keys of original nvd cpe_matches
        nlp_matches = [strip_nlp_match_keys(nlp_match) for nlp_match in nlp_matches]
        cve["cpe_matches_nlp"] += [nlp_match]
    return cves


def handle_newly_assigned_cves(assigned_cves: [{}], db: Database, coll_name: str) -> []:
    """
        Finds outdated nlp cves in a given database, replaces them with their updated version,
        adds the old nlp assignment to "cpe_matches_nlp" and a timestamp to its field "nlp_method".
        Args:
            assigned_cves: Recent CVEs with CPE assignments
            db: mongoDB where collection is stored
            coll_name: name of collection

        Returns:
            outdated_cves: List of CVEs that had NLP generated CPE assignments but were replaced
            by human expert assignments.
        """
    outdated_cves = []
    for assigned_cve in assigned_cves:
        nlp_cve_in_db = db[coll_name].find_one({"cve_id": assigned_cve["cve_id"]})
        if nlp_cve_in_db:
            outdated_cves.append(nlp_cve_in_db)
            outdated_nlp_matches = nlp_cve_in_db["cpe_matches_nlp"].copy()
            for match in outdated_nlp_matches:
                match["nlp_method"]["date_generated"] = nlp_cve_in_db["lastmodified"]
                match["nlp_method"]["description"] = nlp_cve_in_db["description"]
            assigned_cve["cpe_matches_nlp"] = outdated_nlp_matches
            assigned_cve["official_assignment"] = True
            db[coll_name].find_one_and_replace({"cve_id": assigned_cve["cve_id"]},
                                               assigned_cve)
    return outdated_cves


def broadcast_cve_nlp_updates(vulns_to_add: [{}], vulns_to_delete: [{}]):
    if not TOPIC:
        print("No updates notification topic is specified")
        return

    vulns_message = json.dumps({'vulns_add': nvd.vulns_to_list(vulns_to_add),
                                'vulns_delete': nvd.vulns_to_list(vulns_to_delete)})

    try:
        sns = boto3.client('sns')
        _ = sns.publish(TopicArn=TOPIC, Message=vulns_message)
    except Exception as err:
        print('Cannot send message to the AWS SNS topic')
        print(err)


def format_cve_for_db(cve: nvd_model.DefCveItemClass):
    cve_id = cve.cve.cve_data_meta.id
    assigner = cve.cve.cve_data_meta.assigner
    published_date = cve.published_date
    last_modified_date = cve.last_modified_date
    description = cve.cve.description.description_data[0].value
    cwe_info = ""
    if cve.cve.problemtype.problemtype_data[0].description:
        cwe_info = cve.cve.problemtype.problemtype_data[0].description[0].value
    impact_doc = impact_from_cve(cve)
    affected = affected_vendors_from_cve(cve)
    cpe_matches = cpe_matches_from_cve(cve)
    references = references_from_cve(cve)

    formatted_cve = {'cve_id': cve_id,
                     'assigner': assigner,
                     'published': published_date,
                     'lastmodified': last_modified_date,
                     'description': description,
                     'weakness': cwe_info,
                     'impact': impact_doc,
                     'affected': affected,
                     'cpe_matches': cpe_matches,
                     'cpe_matches_nlp': [],
                     'references': references
                     }

    return formatted_cve


def impact_from_cve(cve: nvd_model.DefCveItemClass) -> dict:
    # Get the indentified scores
    cvssv2_basedoc = {}
    cvssv2_exploitabilityscore = 'n.a.'
    cvssv2_impactscore = 'n.a.'
    cvssv3_basedoc = {}
    cvssv3_exploitabilityscore = 'n.a.'
    cvssv3_impactscore = 'n.a.'

    v2_metric = cve.impact.base_metric_v2
    if v2_metric:
        cvssv2_basedoc = v2_metric.cvss_v2.to_dict()
        cvssv2_exploitabilityscore = v2_metric.exploitability_score
        cvssv2_impactscore = v2_metric.impact_score

    v3_metric = cve.impact.base_metric_v3
    if v3_metric:
        cvssv3_basedoc = v3_metric.cvss_v3.to_dict()
        cvssv3_exploitabilityscore = v3_metric.exploitability_score
        cvssv3_impactscore = v3_metric.impact_score

    impact_doc = {'cvss2': cvssv2_basedoc,
                  'cvss2_exploitscore': cvssv2_exploitabilityscore,
                  'cvss2_impactscore': cvssv2_impactscore,
                  'cvss3': cvssv3_basedoc,
                  'cvss3_exploitscore': cvssv3_exploitabilityscore,
                  'cvss3_impactscore': cvssv3_impactscore}
    return impact_doc


def affected_vendors_from_cve(cve: nvd_model.DefCveItemClass) -> dict:
    if not cve.cve.affects:
        return {}
    if not cve.cve.affects.vendor.vendor_data:
        return {}
    affected_vendors = []
    for vendor in cve.cve.affects.vendor.vendor_data:
        vendor_name = vendor.vendor_name
        products = []
        for product in vendor.product.product_data:
            product_name = product.product_name
            product_versions = []
            for version in product.version.version_data:
                product_versions.append({"version": version.version_value,
                                         "version_range": version.version_affected})
            products.append({"product": product_name,
                             "versions": product_versions})
        affected_vendors.append({"vendor": vendor_name, "products": products})

    return affected_vendors


def cpe_matches_from_cve(cve: nvd_model.DefCveItemClass) -> [{}]:
    """
        Args:
            cve: nvd_model:DefCveItemClass
        Returns:
            matches: [{}]
        """
    cpe_matches = []
    for node in cve.configurations.nodes:
        cpe_matches += [match for match in node.cpe_match]
        for child_node in node.children:
            cpe_matches += [match for match in child_node.cpe_match]
    cpe_matches = [nvd_model.DefCpeMatch.to_dict(match) for match in cpe_matches]
    return cpe_matches


def references_from_cve(cve: nvd_model.DefCveItemClass) -> [{}]:
    references = []
    for reference in cve.cve.references.reference_data:
        references.append({"url": reference.url,
                           "name": reference.name,
                           "refsource": reference.refsource,
                           "tags": reference.tags})
    return references


def upload_nlp_cves(cve_items: [{}], db: Database, collection_name: str):
    """
    Inserts CVE Items into a database.
    """
    nlp_upd_count = 0
    for cve in cve_items:
        result = db[collection_name].update_one({"cve_id": cve['cve_id']},
                                                {"$set": cve},
                                                upsert=True)
        if result.acknowledged:
            print(f"Updated {cve['cve_id']} in collection.")
            nlp_upd_count += 1
    print(f"{nlp_upd_count} entries were inserted into or modified in '{collection_name}'")
    return


def vulns_from_nlp_cves(cve_items: {}, vuln_items: dict = {}) -> {}:
    """
    Builds "vulnerabilities" out of CVE items which are present in vulnDB.cve_nlp.
    Output of this function matches the format of nvd.build_vulns(),
     so nvd.upload_vulns(db,vulns, collection) can be used to upload vulns.
    Args:
        cve_items: List of CVE Items imported from vulnDB.cve_nlp
        vuln_items: dict(Product, Configurations)

    Returns:
        vuln_items: dict(Product(vendor,product,platform),
                        configurations[ config([versions],[cves]) ] )
    """
    for cve_item in cve_items:
        products = make_products(cve_item)
        products = nvd._make_products_union(products)

        for product, configs in products.items():
            stored = vuln_items.get(product, [])

            for c1 in configs:
                c1['cves'] = [cve_item["cve_id"]]
                merged = False

                for c2 in stored:
                    merged = merge_cves(c1, into=c2)
                    if merged:
                        break

                if not merged:
                    stored.append(c1)
            vuln_items[product] = stored
    return vuln_items


def make_products(cve_item: dict) -> [{}]:
    """
    Scans (nlp) CPE_matches of a CVE and turns them into "Products".
    Args:
        cve_item: dict with attribute "cpe_matches_nlp"

    Returns:
        Products: [{Product(vendor,product):config[versions[],cves[]]}]
    """
    cpe_matches = cve_item["cpe_matches_nlp"]
    products = []
    for match in cpe_matches:
        cpe_uri = match["cpe_uri"]

        product = vulns.Product(name=cpe_uri.split(":")[3],
                                vendor=cpe_uri.split(":")[4],
                                platform="")

        configuration = {"version": cpe_uri.split(":")[5],
                         "vulnerable": "n.a."}

        version_limit_tags = ["versionEndIncluding", "versionEndExcluding",
                              "versionStartIncluding", "versionStartExcluding"]
        for v_limit in version_limit_tags:
            if v_limit in match.keys():
                configuration[v_limit] = match[v_limit]

        products_item = {product: [configuration]}
        products.append(products_item)

    return products


def merge_cves(conf: dict, into: dict) -> bool:
    if conf.keys() == into.keys() and all(conf[k] == into[k] for k in conf.keys() if k != 'cves'):
        into['cves'] += [v for v in conf['cves'] if v not in into['cves']]
        return True
    else:
        return False


def remove_cves_from_vulns(cves: [{}], db: Database, coll_name: str):
    """
    Iterates through  list of CVEs and removes CVE-IDs from vuln configurations
    in the given database. Vulns with empty configurations are deleted.
    Args:
        cves: list of cve objects that should be removed from the vulns collection
        db: Database on which operations take place.
        coll_name: name of collection

    Returns:

    """
    for cve in cves:
        cve_id = cve["cve_id"]
        vulns_in_coll = list(db[coll_name].find({"configurations.cves": cve_id}))
        for vuln in vulns_in_coll:
            idx = {"vendor": vuln["vendor"],
                   "product": vuln["product"]}
            configs = vuln["configurations"]
            for config in configs:
                if cve_id in config["cves"]:
                    config.remove(cve_id)
                if not config["cves"]:
                    configs.remove(config)
            if not configs:
                db["coll_name"].find_one_and_delete(idx)
            else:
                db["coll_name"].find_one_and_replace(idx, vuln)
    return

# lambda_handler({"action":"update","hours":16}, {})