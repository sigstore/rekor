# Steps

## Cluster Setup

* Created a GKE cluster with Workload Identity enabled
* Created a GCP Service Account (rekor-dev)
* Granted that GSA IAM permissions to be used with Workload Identity
* Paired that GSA with the KSA default in the default namespace
* Gave that GSA Cloud SQL user IAM permissions

## SQL Setup

* Created a Cloud SQL instance for MySQL
* Created a database with default settings
* Set a root user and password
* Used this to setup the database and app user:
https://github.com/google/trillian/blob/2053c7648b44d5de45863c3ad12550b511ad6a14/scripts/resetdb.sh
* To run the script:
  * Get a Cloud Shell from the Cloud Console
  * Get temporary access using "gcloud sql connect".
  * This sets up an shell with access for 5 minutes
  * You can just ctrl+c out of this and then access using whatever you need, in this case the above script.

## Deployments

Setup the SQL configmap with something like:

```
kubectl create configmap cloud-sql --from-literal=connection="project-rekor:us-central1:rekor-dev=tcp:3306"
```

Then deploy with:

```
ko apply -f config/
```
