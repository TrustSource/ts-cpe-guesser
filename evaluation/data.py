#import requests
import json

FETCH_NLP_CVE_URL = "https://rscyxnhkwg.execute-api.eu-central-1.amazonaws.com/Prod/fetch_nlp_cves"
cpe_fields = ["vendor", "product", "version",
              "versionStartIncluding", "versionStartExcluding",
              "versionEndIncluding", "versionEndExcluding"]


def load():
    try:
        cves = json.load(open("nlp_cves.json", "r"))
        return cves
    except FileNotFoundError:
        print("No nlp_cves.json found. Downloading..")
        download(save=True)
    cves = json.load(open("nlp_cves.json", "r"))
    return cves


def download(save=False):
    print("Downloading CVEs from fetchNlpCves API")
    response = requests.get(FETCH_NLP_CVE_URL)
    cves = response.json()["cves_nlp"]
    if save:
        print("Saving into nlp_cves.json..")
        json.dump(cves, open("nlp_cves.json", "w"))
        print("Saved.")
    return cves


class Preprocessing:

    @staticmethod
    def filter_where_entities_in_description(cves: [], entities: []):
        cves_filtered = []
        for cve in cves:
            if Preprocessing.check_entities_in_description(cve, entities):
                cves_filtered.append(cve)
        return cves_filtered

    @staticmethod
    def filter_where_entities_not_in_description(cves: [], entities: []):
        cves_filtered = []
        for cve in cves:
            if not Preprocessing.check_entities_in_description(cve, entities):
                cves_filtered.append(cve)
        return cves_filtered

    @staticmethod
    def check_entities_in_description(cve, entities):
        """Checks whether the values of  entities (e.g. vendor, product, version) appear in a cve description, while
        ignoring all special characters.
        Args:
            cve {}: See keys in data.py
            entities []: List of entities that should appear in the text explicitly
            """
        description = StringComparisons.remove_special_characters(cve["description"])
        description = description.lower()
        for entity in entities:
            entity_value = cve["cpe_match"][entity]
            entity_value = StringComparisons.remove_special_characters(entity_value)
            entity_value = entity_value.lower()
            # Break condition
            if entity_value not in description:
                return False
        # If the loop finishes, all entity values appeared in the description explicitly.
        return True

    @staticmethod
    def preprocess(cves):
        # Fill empty fields with None
        for cve in cves:
            cve["cpe_match_nlp"] = Preprocessing.fill_empty_fields(cve["cpe_match_nlp"])
        return cves

    @staticmethod
    def fill_empty_fields(cpe_match: {}, filling: object = None) -> {}:
        """ Checks if certain versionRange keys are missing and adds them to a cpe_match"""
        for field in cpe_fields:
            if field not in cpe_match.keys():
                cpe_match[field] = filling
        return cpe_match


class StringComparisons:
    @staticmethod
    def strings_equal(a, b):
        return a.lower() == b.lower()

    @staticmethod
    def string_equal_without_special_characters(a, b):
        a = StringComparisons.remove_special_characters(a)
        b = StringComparisons.remove_special_characters(b)
        return a.lower() == b.lower()

    @staticmethod
    def remove_special_characters(s: str) -> str:
        if s is None:
            return "None"
        return ''.join(c for c in s if c.isalnum())
