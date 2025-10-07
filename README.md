# sigma_to_wazuh
Convert Sigma rules to Wazuh rules

## How to:
Clone repository.  

Install Python3 packages: ```pip3 install lxml bs4 ruamel.yaml```

Clone Sigma repository: [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

Update "config.ini" variables where necessary.
- directory: point it to the rules folder in the cloned Sigma repository

Run sigma_to_wazuh.py
- You'll see output of rules that are skipped, rules that error out on loading, followed by a summary of the rules conversion.

## Running converter:

1. Change rule location directory in `config.ini`
2. Run the sigma_to_wazuh.py.
    2.1. If converter has skipped some rules, checkout the output in the cli.
4. Run the normalize_nums.py to perform ids normalization from start id.
5. You can find converted rules in `sigma.xml`

**!!! If you see that some fields are not mapped, check the sigma_full_log.csv for additional info.**
