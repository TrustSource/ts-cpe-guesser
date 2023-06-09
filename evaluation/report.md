# Using OpenAI's GPT-3 API to Extract Vendor, Product and Version information from Natural Language


## Motivation
TrustSource's Vulnerability Lake provides vulnerability accounts of a  tremendous amount of Open Source components. It is capable of doing so by integrating information from multiple authoritative sources on cybersecurity.

One such source is the National Institute of Standards and Technology. It hosts the National Vulnerability Database, or "[NVD](https://nvd.nist.gov/)". The NVD features structured information about individual vulnerabilites, so called [CVEs](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures), in a convenient format which can be accessed directly from their servers. 

The CVEs in these databases contain, among other kinds of information, 
1. A natural language description of the vulnerability in question
2. A list of [CPEs](https://en.wikipedia.org/wiki/Common_Platform_Enumeration) which specify  the afflicted software configurations.

TrustSource uses these CPEs to automatically assign vulnerabilities to software components. 
Unfortunately, this approach is not always viable. When a vulnerability has been registered just recently and 
is still under investigation, the list of CPEs usually follows the announcement after a few days, whereas a description is available right away.

Hence, we considered training a language model (GPT-3) to extract the CPE fields
`vendor`, `product`, `version` and version ranges like `versionStartIncluding` from the natural language descriptions of
new CVEs to be as quick as possible about warning our customers when a
component they use might be subjected to a vulnerability.
## Approach

### Data
We used CVE data from the NVD-2021-CVE catalog, accessed in July 2022, for fine-tuning a GPT-3 model to perform _Named Entity Extraction_ on CVE descriptions. The entities to be extracted were `vendor`, `product`, `version` and the four version ranges
`version[Start|End][In|Ex]cluding`. Have a look at the __positive examples__ or __negative examples__ below for
showcases of _named entity extraction_.

We only included training data where 
    
* the list of officially assigned CPEs was shorter than 3
* a vendor/product configuration, such as google/chrome, is not already part of the training set
* vendor, product & versions are all mentioned explicitly in the description

This left us with 665 examples of descriptions with matched CPEs from the NVD-2021-CVE catalog . 

### Model Training
We followed the openAI API guide to bring the training set into the correct format
and used the API to initiate fine-tuning of their _Curie_ Model. CVE descriptions were inputs,
line-separated entities were outputs. 

## Results
The model was evaluated on 3048 officially confirmed CVE descriptions modified between October 6th, 2022 and March 28th, 2023. 
A model prediction was considered "correct", when the model output was equal to the values in the official CPE assignment. 
To reasonably relax the constraints, we also removed non-alphanumeric characters from both, model- & official, strings.

### All CVEs (3048)
Naively testing the model performance on all CVEs, including those where entities don't appear explicitly in the 
descriptions yielded the following performances. 

| Entity                |Accuracy | Accuracy (no special characers)|                              
|-----------------------|---------|----------
| product               | 0.43	 | 0.5
| vendor                | 0.46    | 0.5       
| version               | 0.68	 | 0.76
| versionEndExcluding   | 0.58	 | 0.58
| versionEndIncluding   | 0.7	 | 0.87
| versionStartExcluding | 0.99	 | 0.99
| versionStartIncluding | 0.84	 | 0.84

Eliminating special characters, at least in half of the cases for all entities, the model generated strings which perfectly matched the strings that were officially assigned to the CVEs.

### Filtered CVEs
We ran the evaluation again, only including CVEs, where the entities of interest were
explicitly mentioned in the descriptions. Since, technically, NER should not be possible when this condition isn't fulfilled.

#### Accuracies depending on whether entities appear in the description
| Entity  | Accuracy (no special characters) | in description| count (out of 3048) |
|---------|----------------------------------|--------       |---------------------|
| product | 0.66                             | yes           | 2182                |
| product | 0.12                             | no            | 866                 |
| vendor  | 0.66                             | yes           | 1549                |
| vendor  | 0.24                             | no            | 1499                |
| version | 0.66                             | yes           | 2671                |
| version | 0.09                             | no            | 377                 |



As expected, the model performs significantly better, when product (0.66 vs 0.12),
vendor (0.76 vs 0.24) and version (0.86 vs 0.09) are explicitly mentioned in the CVE descriptions. 


It is striking that the model was able to correctly identify 24% of vendors even though they did not appear explicitly in the descriptions. 
The model correctly inferred the vendor in these cases when 
1. The product is very well known. That would be the case for "chrome" or "android" for both of which the model correctly determined "google" to be the vendor.
2. In some instances, when the correct vendor name is "<product-name>_project"



#### Positive Examples
|Description           |Official | Model |                              
|----------------      |---------|----------|
|Use after free in PDF in Google Chrome prior to 105.0.5195.125 allowed a remote attacker to potentially  exploit heap corruption via a crafted PDF file.        | product : chrome ,  <br> vendor: google <br>  version: * <br> versionEndExcluding: 105.0.5195.125 |product : chrome ,  <br> vendor: google <br>  version: * <br> versionEndExcluding: 105.0.5195.125 
|mojoPortal v2.7 was discovered to contain a path traversal vulnerability via the "f" parameter at /DesignTools/CssEditor.aspx. This vulnerability allows authenticated attackers to read arbitrary files in the system.        | product : mojoportal,  <br> vendor: mojoportal <br>  version: 2.7.0.0|product : mojo_portal <br> vendor: mojo_portal <br>  version: 2.7* <br> 

*This version is considered  wrong in our statistics

#### Negative Examples
|Description           |Official | Model |                              
|----------------      |---------|----------
|Windows Active Directory Certificate Services Security Feature Bypass.| product : windows_10 <br> vendor: microsoft <br>  version: - <br> |product : active_directory_certification_services <br> vendor: windows <br>   version: * <br> versionEndExcluding: 1.1.87 |
|Multiple heap buffer overflows in tiffcrop.c utility in libtiff library Version 4.4.0 allows attacker to trigger unsafe or out of bounds memory access via crafted TIFF image file which could result into application crash, potential information disclosure or any other context-dependent impact | product : libtiff <br> vendor: libtiff <br>  version: * <br> versionEndIncluding: 4.4.0 <br> versionStartIncluding : 3.9.0 | product : tiffcrop <br> vendor: tiffcrop_project <br> version: * <br> versionEndExcluding: 4.4.0 |


## Conclusion
Given that the model was trained on surprisingly little training data and the comparatively low-effort training procedure, the model performs reasonably well at extracting vendor, product and version information from CVE descriptions, assuming that the entities are explicitly mentioned. 

If a language model like GPT-3 is to be deployed for the purpose of early vulnerability assignments and alerts, it would greatly benefit from somewhat standardized description scheme, where vendors and products are mentioned explicitly. Furthermore, training another model with more training data could yield improvements as well. 


## Try it yourself
If you want to see different results, modify `run()` in `script.py` to yield the results
that you would like to see.