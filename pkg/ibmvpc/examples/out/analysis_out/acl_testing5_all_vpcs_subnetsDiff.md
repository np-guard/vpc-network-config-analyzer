# Connectivity diff between VPC test-vpc-ky1 and VPC test-vpc-ky2
## Subnets diff report
| type | src |  dst | conn1 | conn2 | subnets-diff-info |
|------|-----|------|-------|-------|-------------------|
| added | sub2-1-ky | Public Internet 8.8.8.0/29,8.8.8.9-8.8.8.15 | No Connections | protocol: UDP dst-ports: 53 |  |
| changed | sub1-1-ky | sub1-2-ky | protocol: TCP | protocol: TCP * |  |
| changed | sub1-1-ky | sub1-3-ky | protocol: TCP | protocol: TCP * |  |
| changed | sub2-1-ky | Public Internet 8.8.8.8/32 | protocol: UDP dst-ports: 53 | protocol: UDP dst-ports: 43,53 |  |
| removed | sub1-2-ky | sub1-1-ky | protocol: TCP | No Connections |  |
| removed | sub1-3-ky | sub1-1-ky | protocol: TCP | No Connections |  |

connections are stateful (on TCP) unless marked with *
