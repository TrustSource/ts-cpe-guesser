# ts-cpe-guesser
All resources related to NLP based CPE generation in the TrustSource ecosystem.


## lambdas
Current lambda handlers are implemented in
 * `cpe_extraction.py` - Essentially API wrapper for nlp.py
 * `fetch_nlp_cves.py` - Fetches data from the collection nlp_cves
 * `update_cve_nlp.py` - This lambda function is situated in ts-vulndb-crawler. It relies on the ts-vulndb package on codeartifact. When deciding to deploy it from here, make sure that ts-vulndb is installed as  `sam build` runs.

`nlp.py` is the core module, which uses the openAI API to call GPT3 with a CVE description. The lambda functions listed above rely on this module.

_NOTE_: Make sure to properly deregister the lambda functions from the stack ts-vulndb-crawler, where they have been deployed and are running now before deciding to redeploy them from this repo. 


## evaluation
After generating CPEs for CVEs over the last 6 months, we have created an evaluation script and corresponding report. They are available in this directory.
