import data
import evaluation

from pprint import pprint


def run():
    cves = data.load()
    comparison_method = data.StringComparisons.string_equal_without_special_characters
    filter_method = data.Preprocessing.filter_where_entities_in_description

    for entity in data.cpe_fields:
        # Only include cve matches where vendor, product, version, etc. appear in description
        cves_filtered = filter_method(cves, entities=[entity])

        cves_filtered = data.Preprocessing.preprocess(cves_filtered)

        accuracies = evaluation.calculate_accuracies(cves_filtered, comparison_method)
        result = {"accuracies": accuracies,
                  "comparison": comparison_method,
                  "filter": f"{filter_method} entity: {entity}",
                  "total": len(cves),
                  "filtered": len(cves_filtered),
                  "excluded": len(cves)-len(cves_filtered)}

        pprint(result)


if __name__ == "__main__":
    run()