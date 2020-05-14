import requests
import json
import time
import boto3
import os

# default
# clair_host = "http://0.0.0.0:6060/v1/layers"
clair_host = "http://<clair-server-hostname>/v1/layers"

# If Its a docker native registry use library/ as prefix in the repo name.
# For example, "library/nginx" for nginx image.

repo = os.getenv('ENV_IMG_REPOSITORY')
tag = os.getenv('ENV_IMG_TAG')
account_id = '<account_id>'
region = 'ap-south-1'

# print(repo, tag)
# Getting layers from docker registry.


def docker_auth():

    login_template = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repository}:pull"
    token = requests.get(login_template.format(
        repository=repo), json=True).json()["token"]
    get_manifest_template = "https://registry-1.docker.io/v2/{repository}/manifests/{tag}"
    manifest = requests.get(
        get_manifest_template.format(repository=repo, tag=tag),
        headers={"Authorization": "Bearer {}".format(
            token), "Accept": "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.v1+prettyjws"},
    ).json()

    return manifest


# It will authenticate with ECR regitry and get a dict of layers to pass to clair for scanning.
def ecr_auth(account_id):

    client = boto3.client('ecr', region_name=region)
    response = client.get_authorization_token(
        registryIds=[
            # Account ID.
            account_id,
        ]
    )
    token = response["authorizationData"][0]["authorizationToken"]

    get_manifest_template = "https://{account_id}.dkr.ecr." + \
        region+".amazonaws.com/v2/{repository}/manifests/{tag}"

    manifest = requests.get(
        get_manifest_template.format(
            repository=repo, tag=tag, account_id=account_id),
        headers={"Authorization": "Basic {}".format(
            token), "Accept": "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.v1+prettyjws"},
    ).json()

    return manifest, token


def submit_layer():

    manifest, token = ecr_auth(account_id)

    base_name = manifest["config"]["digest"].replace("sha256:", "")

    parent_hash = ""

    registry = "https://" + account_id + ".dkr.ecr." + region + ".amazonaws.com"

    for layers in manifest["layers"]:
        layer_name = layers["digest"].replace("sha256:", "")
        # print("-- Layer hash: " + base_name + layer_name)
        requests_body = {
            "Layer": {
                "Name": base_name + layer_name,
                "Path": registry + "/v2/" + repo + "/blobs/" + layers["digest"],
                "Headers": {
                    "Authorization": "Basic " + token
                },
                "ParentName": parent_hash,
                "Format": "Docker"
            }
        }

        parent_hash = base_name + layer_name

        requests.post(clair_host, data=json.dumps(requests_body))
        # if post_layer.status_code != 201:
        #    print("Getting " + status_code + " while submitting layer. " + "Response: \n" + post_layer.text)


def get_layer_features():

    vulnerabilities = []

    manifest, token = ecr_auth(account_id)

    base_name = manifest["config"]["digest"].replace("sha256:", "")

    last_layer = []

    # Getting the last layer.
    for layers in manifest["layers"]:

        layer_name = layers["digest"].replace("sha256:", "")

        last_layer.append(layer_name)

    get_scan_report = requests.get(
        clair_host + "/" + base_name + last_layer[-1] + "?features&vulnerabilities")

    report = json.loads(get_scan_report.text)

    total_vulns = 0
    high_vulns = 0
    # Getting the vulnerabilities.
    for features in report["Layer"]["Features"]:
        for key, value in features.items():
            if key == "Vulnerabilities":
                total_vulns += len(value)
                for items in value:
                    # This will print all vulnerabilities.
                    # print(items)
                    if items['Severity'] == "High":
                        high_vulns += len(items['Severity'])
                        # print(items)
                        vulnerabilities.append(items)

    print(vulnerabilities)
    print("\nTotal Vulnerabilities: " + str(total_vulns) +
          "\nHigh Severity: " + str(high_vulns))
    print("Repository: " + repo + "\nTag: " + tag)


if __name__ == '__main__':

    try:
        print("-------", repo, tag)
        print("-- Initiating scan." + " Repository:" + repo + ":" + tag)
        print("-- Submitting layers...")
        submit_layer()
        print("-- Getting report...")
        time.sleep(10)
        get_layer_features()
        print("Exiting.")
    except Exception as error:
        print("--- Unexpected error occured. Exiting...", error)
        raise
