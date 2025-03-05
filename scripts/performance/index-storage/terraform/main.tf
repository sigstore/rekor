// Copyright 2024 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

provider "google" {
    project = var.project
    zone = var.zone
    region = var.region
}

module "network" {
    source = "git::https://github.com/sigstore/terraform-modules.git//terraform/gcp/modules/network?ref=385f4490a88608e156bfb3530f098aa5f2fd3722"

    region = var.region
    project_id = var.project
    cluster_name = "rekor"
}

module "bastion" {
    source = "git::https://github.com/sigstore/terraform-modules.git//terraform/gcp/modules/bastion?ref=385f4490a88608e156bfb3530f098aa5f2fd3722"

    project_id = var.project
    region = var.region
    zone = var.zone
    network = module.network.network_name
    subnetwork = module.network.subnetwork_self_link
    tunnel_accessor_sa = var.tunnel_accessor_sa

    depends_on = [
        module.network,
    ]
}

module "mysql" {
    source = "git::https://github.com/sigstore/terraform-modules.git//terraform/gcp/modules/mysql?ref=385f4490a88608e156bfb3530f098aa5f2fd3722"

    project_id = var.project
    region = var.region
    cluster_name = "rekor"
    database_version = "MYSQL_8_0"
    availability_type = "ZONAL"
    network = module.network.network_self_link
    instance_name = "rekor-perf-tf"
    require_ssl = false

    depends_on = [
        module.network
    ]
}

module "gke_cluster" {
    source = "git::https://github.com/sigstore/terraform-modules.git//terraform/gcp/modules/gke_cluster?ref=385f4490a88608e156bfb3530f098aa5f2fd3722"

    region = var.region
    project_id = var.project
    cluster_name = "rekor"
    network = module.network.network_self_link
    subnetwork = module.network.subnetwork_self_link
    cluster_secondary_range_name = module.network.secondary_ip_range.0.range_name
    services_secondary_range_name = module.network.secondary_ip_range.1.range_name
    cluster_network_tag = ""
    bastion_ip_address = module.bastion.ip_address

    depends_on = [
        module.network,
        module.bastion,
    ]
}

module "rekor" {
    source = "git::https://github.com/sigstore/terraform-modules.git//terraform/gcp/modules/rekor?ref=385f4490a88608e156bfb3530f098aa5f2fd3722"

    region = var.region
    project_id = var.project
    cluster_name = "rekor"

    enable_attestations = false

    redis_cluster_memory_size_gb = "16"

    network = module.network.network_self_link
    dns_zone_name = var.dns_zone
    dns_domain_name = var.dns_domain

    depends_on = [
        module.network,
        module.gke_cluster
    ]
}

module "oslogin" {
    source = "git::https://github.com/sigstore/terraform-modules.git//terraform/gcp/modules/oslogin?ref=385f4490a88608e156bfb3530f098aa5f2fd3722"

    project_id = var.project
    count = 1
    oslogin = {
        enabled = true
        enabled_with_2fa = false
    }
    instance_os_login_members = {
        bastion = {
            instance_name = module.bastion.name
            zone = module.bastion.zone
            members = var.oslogin_members
        }
    }

    depends_on = [
        module.bastion,
    ]
}

output "mysql_pass" {
    value = module.mysql.mysql_pass
    sensitive = true
}
