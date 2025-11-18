from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

secrets = SecretsCollection()
with default_settings():
    secrets.scan_file('test_data/config.ini')
    secrets.scan_files(".password")


import json
print(json.dumps(secrets.json(), indent=2))