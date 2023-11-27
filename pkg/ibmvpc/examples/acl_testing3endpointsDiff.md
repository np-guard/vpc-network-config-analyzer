# Diff between VPC test-vpc1-ky and VPC test-vpc2-ky
## Endpoints diff report
| type | src |  dst | conn1 | conn2 | vsis-diff-info |
|------|-----|------|-------|-------|----------------|
| removed | vsi1-ky[10.240.10.4] | Public Internet 161.26.0.0/16 | protocol: UDP * | No connection |  |
| removed | vsi1-ky[10.240.10.4] | vsi2-ky[10.240.20.4] | protocol: TCP,UDP | No connection |  |

connections are stateful unless marked with *
