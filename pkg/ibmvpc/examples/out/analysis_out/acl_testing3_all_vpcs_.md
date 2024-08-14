# Endpoint connectivity for VPC test-vpc1-ky
| src | dst | conn |
|-----|-----|------|
| db-endpoint-gateway-ky[10.240.30.7] | vsi1-ky[10.240.10.4] | protocol: ICMP,UDP |
| db-endpoint-gateway-ky[10.240.30.7] | vsi1-ky[10.240.10.4] | protocol: TCP *  |
| db-endpoint-gateway-ky[10.240.30.7] | vsi3a-ky[10.240.30.5] | All Connections |
| db-endpoint-gateway-ky[10.240.30.7] | vsi3b-ky[10.240.30.6] | All Connections |
| db-endpoint-gateway-ky[10.240.30.7] | vsi3c-ky[10.240.30.4] | All Connections |
| vsi1-ky[10.240.10.4] | Public Internet 161.26.0.0/16 | protocol: UDP |
| vsi1-ky[10.240.10.4] | vsi2-ky[10.240.20.4] | protocol: TCP,UDP |
| vsi2-ky[10.240.20.4] | Public Internet 142.0.0.0/8 | protocol: ICMP |
| vsi2-ky[10.240.20.4] | vsi1-ky[10.240.10.4] | All Connections |
| vsi3a-ky[10.240.30.5] | db-endpoint-gateway-ky[10.240.30.7] | All Connections |
| vsi3a-ky[10.240.30.5] | vsi1-ky[10.240.10.4] | protocol: ICMP,UDP |
| vsi3a-ky[10.240.30.5] | vsi1-ky[10.240.10.4] | protocol: TCP *  |
| vsi3a-ky[10.240.30.5] | vsi3b-ky[10.240.30.6] | All Connections |
| vsi3a-ky[10.240.30.5] | vsi3c-ky[10.240.30.4] | All Connections |
| vsi3b-ky[10.240.30.6] | db-endpoint-gateway-ky[10.240.30.7] | All Connections |
| vsi3b-ky[10.240.30.6] | vsi1-ky[10.240.10.4] | protocol: ICMP,UDP |
| vsi3b-ky[10.240.30.6] | vsi1-ky[10.240.10.4] | protocol: TCP *  |
| vsi3b-ky[10.240.30.6] | vsi3a-ky[10.240.30.5] | All Connections |
| vsi3b-ky[10.240.30.6] | vsi3c-ky[10.240.30.4] | All Connections |
| vsi3c-ky[10.240.30.4] | db-endpoint-gateway-ky[10.240.30.7] | All Connections |
| vsi3c-ky[10.240.30.4] | vsi1-ky[10.240.10.4] | protocol: ICMP,UDP |
| vsi3c-ky[10.240.30.4] | vsi1-ky[10.240.10.4] | protocol: TCP *  |
| vsi3c-ky[10.240.30.4] | vsi3a-ky[10.240.30.5] | All Connections |
| vsi3c-ky[10.240.30.4] | vsi3b-ky[10.240.30.6] | All Connections |

TCP connections for which response is not permitted are marked with * 
