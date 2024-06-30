# Connectivity diff between VPC test-vpc-ky1 and VPC test-vpc-ky2
## Subnets diff report
| type | src |  dst | conn1 | conn2 | subnets-diff-info |
|------|-----|------|-------|-------|-------------------|
| added | sub2-1-ky | Public Internet 8.8.8.0/29,8.8.8.9-8.8.8.15 | No Connections | UDP dst-ports: 53 |  |
| changed | sub1-1-ky | sub1-2-ky | TCP | TCP *  |  |
| changed | sub1-1-ky | sub1-3-ky | TCP | TCP *  |  |
| changed | sub2-1-ky | Public Internet 8.8.8.8/32 | UDP dst-ports: 53 | UDP dst-ports: 43,53 |  |
| removed | sub1-2-ky | sub1-1-ky | TCP | No Connections |  |
| removed | sub1-3-ky | sub1-1-ky | TCP | No Connections |  |

TCP connections for which response is not permitted are marked with * 
