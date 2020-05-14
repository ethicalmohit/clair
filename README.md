# Clair Scanner

Ths repository has dockerfile and the clair client script. It can be invoked by the lambda using cloudwatch event rule at every push made to ECR registry.

## Capabilities

Authenticate with the Docker/ECR registry. <br />
Fetch the layers of the image:tag from the repository. <br />
Submit the layers to the clair server. <br />
Get the report of the submitted layer and print it on STDOUT.

## Build Commands

```
docker build -t clair-scan .
docker tag clair-scan:latest <repo_url>
docker push <repo_url>
```
