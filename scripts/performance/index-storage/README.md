Rekor Performance Tester
========================

Scripts to repeatably gather performance metrics for index storage insertion and
retrieval in rekor.

Usage
-----

Use terraform to set up the services in GCP:

```
cd terraform
terraform init
terraform plan
terraform apply
```

Copy or clone this repository on to the bastion VM that terraform instantiates.
Run this script from there:

```
export INSERT_RUNS=<N> # The number of inserts to perform and measure. This doesn't need to be terribly high.
export SEARCH_ENTRIES=<M> # The number of entries to upload to the database out of band to search against. This should be sufficiently high to represent a real database.
export INDEX_BACKEND=<redis|mysql> # The index backend to test against
export REGION=<region> # The GCP region where the rekor services are deployed
./index-performance.sh
```

On the first run, `indices.csv` will be populated with fake search entries,
which will take a while depending on how big $SEARCH_ENTRIES is. This only
happens once as long as indices.csv is not removed.

Run `index-performance.sh` against each backend. Then plot the results:

```
./plot.sh
```

Copy the resulting `graph.png` back to your local host.
