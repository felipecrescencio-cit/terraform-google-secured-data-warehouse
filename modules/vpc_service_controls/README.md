# VPC Service Controls submodule
This module creates service perimeters using [VPC Service Controls](https://cloud.google.com/vpc-service-controls/docs/overview). The Secured Data Warehouse blueprint uses these perimeters to protect the project resources and the data that you store in BigQuery.

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| access\_context\_manager\_policy\_id | The id of the default Access Context Manager policy (see https://cloud.google.com/access-context-manager/docs/overview). Can be obtained by running `gcloud access-context-manager policies list --organization YOUR-ORGANIZATION_ID --format="value(name)"`. | `number` | n/a | yes |
| access\_level\_allowed\_encryption\_statuses | Condition - A list of allowed encryption statuses. An empty list allows all statuses. For more information, see https://cloud.google.com/access-context-manager/docs/reference/rest/Shared.Types/DeviceEncryptionStatus. | `list(string)` | <pre>[<br>  "ENCRYPTED"<br>]</pre> | no |
| access\_level\_ip\_subnetworks | Condition - A list of CIDR block IP subnetwork specification. May be IPv4 or IPv6. Note that for a CIDR IP address block, the specified IP address portion must be properly truncated (that is, all the host bits must be zero) or the input is considered malformed. For example, "192.0.2.0/24" is accepted but "192.0.2.1/24" is not. Similarly, for IPv6, "2001:db8::/32" is accepted whereas "2001:db8::1/32" is not. The originating IP of a request must be in one of the listed subnets in order for this Condition to be true. If empty, all IP addresses are allowed. | `list(string)` | `[]` | no |
| access\_level\_regions | Condition - The request must originate from one of the provided countries or regions. Format: A valid ISO 3166-1 alpha-2 code. | `list(string)` | `[]` | no |
| access\_level\_require\_corp\_owned | Condition - Whether the device needs to be company owned. | `bool` | `true` | no |
| access\_level\_require\_screen\_lock | Condition - Whether or not screenlock is required for the DevicePolicy to be true. | `bool` | `true` | no |
| commom\_suffix | A commom suffix to be used in the module. | `string` | `""` | no |
| org\_id | The GCP Organization ID. | `string` | n/a | yes |
| organization\_has\_mdm\_license | Whether the organization has an MDM license (see https://cloud.google.com/access-context-manager/docs/use-mobile-devices). Will allow require\_screen\_lock, require\_corp\_owned and allowed\_encryption\_statuses to be used on policy access level. | `bool` | `false` | no |
| perimeter\_additional\_members | The list of additional members to be added on perimeter access. Prefix of group: user: or serviceAccount: is required. | `list(string)` | `[]` | no |
| project\_id | The ID of the project in which the service account will be created. | `string` | n/a | yes |
| region | The region in which the subnetwork will be created. | `string` | n/a | yes |
| restricted\_services | The list of services to be restricted by VPC Service Controls. | `list(string)` | n/a | yes |
| subnet\_ip | The CDIR IP range of the subnetwork. | `string` | n/a | yes |
| terraform\_service\_account | The email address of the service account that will run the Terraform code. | `string` | n/a | yes |
| vpc\_name | The name of the network. | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| access\_level\_name | The access level name for the Access Context Manager. |
| network\_name | The name of the VPC being created. |
| network\_self\_link | The URI of the VPC being created. |
| project\_number | The project number that is included on the perimeter. |
| service\_perimeter\_name | The service perimeter name for the Access Context Manager. |
| subnets\_ips | The IPs and CIDRs of the subnets being created. |
| subnets\_names | The names of the subnets being created. |
| subnets\_regions | The region where the subnets will be created. |
| subnets\_self\_links | The self-links of subnets being created. |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->