# Connectivity diff between VPC test-vpc1-ky and VPC test-vpc2-ky
## Endpoints diff report
| type | src |  dst | conn1 | conn2 | vsis-diff-info |
|------|-----|------|-------|-------|----------------|
| changed | vsi2-ky[10.240.20.4] | vsi1-ky[10.240.10.4] | All Connections | TCP * ; ICMP,UDP |  |
| removed | vsi1-ky[10.240.10.4] | Service Network 161.26.0.0/16 | UDP | No Connections |  |
| removed | vsi1-ky[10.240.10.4] | vsi2-ky[10.240.20.4] | TCP,UDP | No Connections |  |

TCP connections for which response is not permitted are marked with * 
