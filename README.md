# ts-cpe-guesser
All resources related to NLP based CPE generation in the TrustSource ecosystem.

> [!WARNING]
> **PLEASE NOTE:** We stopped further development on this client. You may still use it, but it will most likely only receive bug fixes. There are thoughts about another trial based on  

## lambdas
Current lambda handlers are implemented in
 * `cpe_extraction.py` - Essentially API wrapper for nlp.py
 * `fetch_nlp_cves.py` - Fetches data from the collection nlp_cves
 * `update_cve_nlp.py` - This lambda function is situated in ts-vulndb-crawler. It relies on the ts-vulndb package on codeartifact. When deciding to deploy it from here, make sure that ts-vulndb is installed as  `sam build` runs.

`nlp.py` is the core module, which uses the openAI API to call GPT3 with a CVE description. The lambda functions listed above rely on this module.

_NOTE_: Make sure to properly deregister the lambda functions from the stack ts-vulndb-crawler, where they have been deployed and are running now before deciding to redeploy them from this repo. 


## evaluation
After generating CPEs for CVEs over the last 6 months, we have created an evaluation script and corresponding report. They are available in this directory.

## observations
Durinng 2023 we ran this CPE guesser on a daily base against the then NVD CVE-in-analysis-feed. These CPEs are still under analysis, not yet confirmed and do not have CPEs or pUrls attached. The guesser should determine the matching components based on the description. we later evaluated our guesses against the real definitions we typically received a few days later. 
Despite a lot of tuning efforts, we were not able to improve a better hit rate than 76.9%. This leaves too much space for false positives, so we decided to focus on other topics first. Since AI models meanwhile improved, it might be worth returning. If you are interested to run a few test together with us, [reach out](https://www.trustsource.io/contact), we are happy to haear from you!
