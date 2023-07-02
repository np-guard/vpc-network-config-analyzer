## Endpoint connectivity report
| src | dst | conn |
|-----|-----|------|
| vsi1-ky[10.240.10.4] | PublicInternet [161.26.0.0/16] | protocol: UDP   |
| vsi1-ky[10.240.10.4] | vsi2-ky[10.240.20.4] | protocol: TCP,UDP   |
| vsi2-ky[10.240.20.4] | PublicInternet [142.0.0.0/8] | protocol: ICMP   |
| vsi2-ky[10.240.20.4] | vsi1-ky[10.240.10.4] | All Connections |
| vsi3a-ky[10.240.30.5] | vsi1-ky[10.240.10.4] | All Connections |
| vsi3a-ky[10.240.30.5] | vsi3b-ky[10.240.30.6] | All Connections |
| vsi3a-ky[10.240.30.5] | vsi3c-ky[10.240.30.4] | All Connections |
| vsi3b-ky[10.240.30.6] | vsi1-ky[10.240.10.4] | All Connections |
| vsi3b-ky[10.240.30.6] | vsi3a-ky[10.240.30.5] | All Connections |
| vsi3b-ky[10.240.30.6] | vsi3c-ky[10.240.30.4] | All Connections |
| vsi3c-ky[10.240.30.4] | vsi1-ky[10.240.10.4] | All Connections |
| vsi3c-ky[10.240.30.4] | vsi3a-ky[10.240.30.5] | All Connections |
| vsi3c-ky[10.240.30.4] | vsi3b-ky[10.240.30.6] | All Connections |