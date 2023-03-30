import data


def count_matches(cves, comparison):
    """
    This function compares nlp assigned CVE matches with officially assigned CPE matches.
    Expects that data hsa already been preprocessed and pre-selected.

    Args:
        cves (list): Each item has dict_keys(['cve_id', 'description', 'cpe_match', 'cpe_match_nlp', 'last_modified'])
        comparison (function): which takes 2 strings as args and returns whether they are equal to some criterion
    """
    cpe_fields = data.cpe_fields
    correct_counts = {field: 0 for field in cpe_fields}

    for cve in cves:
        cpe_match = cve["cpe_match"]
        cpe_match_nlp = cve["cpe_match_nlp"]
        correct_counts = update_counts(cpe_match, cpe_match_nlp,
                                       cpe_fields, correct_counts,
                                       comparison)
    return {"counts": correct_counts, "comparison": str(comparison)}


def calculate_accuracies(cves, comparison):
    """
    Returns
        results (dict): keys
            * ["vendor","product","version","versionRange","start|End|Excluding"]
    """
    cpe_fields = data.cpe_fields
    correct_counts = {field: 0 for field in cpe_fields}

    for cve in cves:
        cpe_match = cve["cpe_match"]
        cpe_match_nlp = cve["cpe_match_nlp"]
        correct_counts = update_counts(cpe_match, cpe_match_nlp,
                                       cpe_fields, correct_counts,
                                       comparison)

    # convert counts into percentages
    accuracies = {field: correct_counts[field]/len(cves) if len(cves) > 0 else "-" for field in cpe_fields}

    return accuracies


def update_counts(cpe_match: {}, cpe_match_nlp: {}, cpe_fields: [], counts: {}, comparison):
    """Compares cpe_fields in two cpe matches and increments counters in the corresponding field of the counts dict.
    Heavily relies on being called correctly by calculate_accuracies.
    """
    for field in cpe_fields:   # cpe_fields := [vendor, product, version, ...]
        if comparison(cpe_match[field], cpe_match_nlp[field]):
            counts[field] += 1
    return counts

