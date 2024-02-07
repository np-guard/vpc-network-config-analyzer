# Connectivity for VPC test-vpc-ky
## Subnets connectivity report
| src | dst | conn |
|-----|-----|------|
| sub1-1-ky | Public Internet 8.8.8.8/32 | protocol: UDP dst-ports: 53 |
| sub1-1-ky | sub1-2-ky | protocol: TCP |
| sub1-1-ky | sub1-3-ky | protocol: TCP |
| sub1-2-ky | sub1-1-ky | protocol: TCP |
| sub1-2-ky | sub1-3-ky | protocol: TCP |
| sub1-3-ky | sub1-1-ky | protocol: TCP |
| sub1-3-ky | sub1-2-ky | protocol: TCP |
| sub2-1-ky | Public Internet 8.8.8.8/32 | protocol: UDP dst-ports: 53 |
| sub2-1-ky | sub2-2-ky | All Connections |
| sub2-2-ky | sub2-1-ky | All Connections |
