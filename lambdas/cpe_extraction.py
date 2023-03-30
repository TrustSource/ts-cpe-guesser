"""
This module extracts [vendor],[product],[version] & [version_limit] information
from texts in natural language. The extraction is accomplished through
"Named Entity Recognition" (NER). NER is performed by a fine-tuned variant
of openAI's Generative Pre-trained Transformer 3 (GPT-3).

The model was fine-tuned with data from the NVD-2021-CVE-Catalog
(Accessed in July 2022). CVE descriptions were inputs, selected CPE fields
were outputs.

A CPE string is artificially reconstructed from the data.

GPT-3 is accessed through an API-Call to openAI.
"""

import nlp
import json

CHAR_LIMIT_MSG = "Description unusually long. \
Trimmed to 1000 characters. Consider reviewing the input."


def lambda_handler(event: dict, context) -> dict:
    """
    Args:
        event:
            valid event keys: ["description"] : (str)
    Returns:
        response:
                response dict with "status" and "body".
                Response body (json str):
                    keys: ["vendor","product","version","description","extraction_method")
                    optional keys: r"version[(Start)|(End)][(In)|(Ex)]cluding"
    """
    description = event["description"]
    if len(description) > 1000:
        print(CHAR_LIMIT_MSG)
        description = description[:1000]  # Trim to avoid high costs and unnecessary parsing
    method = "openai"

    config = nlp.generate_cpe_match(description, method)
    config["cpe"] = make_cpe_uri(config)

    print("Config Data Extracted from Description.")
    for key, value in config.items():
        print(f"{key} : {value}")

    body = json.dumps(config)

    return {"status": "200", "body": body}


def extract_cpe(description: str) -> dict:
    if len(description) > 1000:
        print(CHAR_LIMIT_MSG)
        description = description[:1000]  # Trim to avoid high costs and unnecessary parsing
    cpe_config = nlp.generate_cpe_match(description, "openai")
    cpe_config["cpe"] = make_cpe_uri(cpe_config)
    return cpe_config


def make_cpe_uri(config: dict) -> str:
    """
    Creates a CPE Uri from a 'config' as received by nlp.genereate_cpe_match
    Args:
        config: dict with keys ["vendor","product","version"]
    Returns:
        cpe_uri: well-formed CPE 2.3 string featuring vendor, product and version
    """
    vendor = config["vendor"]
    product = config["product"]
    version = config["version"]
    cpe_uri = f"cpe:2.3:*:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    return cpe_uri

