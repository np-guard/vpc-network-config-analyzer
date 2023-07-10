## Endpoint connectivity report
| src | dst | conn |
|-----|-----|------|
| Public Internet [1.0.0.0/8] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [100.128.0.0/9] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [11.0.0.0/8] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [128.0.0.0/5] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [142.0.0.0/8] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [143.0.0.0/8] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [147.235.219.206/32] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [147.235.219.207/32] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [147.235.219.208/28] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [161.26.0.0/16] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [161.27.0.0/16] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [169.255.0.0/16] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [172.32.0.0/11] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [192.0.1.0/24] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [192.0.3.0/24] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [192.169.0.0/16] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [192.88.100.0/22] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [198.20.0.0/14] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [198.51.101.0/24] | vsi2-ky[10.240.20.4] | All Connections |
| Public Internet [203.0.114.0/23] | vsi2-ky[10.240.20.4] | All Connections |
| vsi1-ky[10.240.10.4] | Public Internet [161.26.0.0/16] | protocol: UDP   * |
| vsi1-ky[10.240.10.4] | vsi2-ky[10.240.20.4] | protocol: TCP,UDP   |
| vsi2-ky[10.240.20.4] | Public Internet [1.0.0.0/8] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [100.128.0.0/9] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [11.0.0.0/8] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [128.0.0.0/5] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [142.0.0.0/8] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [143.0.0.0/8] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [147.235.219.206/32] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [147.235.219.207/32] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [147.235.219.208/28] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [161.26.0.0/16] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [161.27.0.0/16] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [169.255.0.0/16] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [172.32.0.0/11] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [192.0.1.0/24] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [192.0.3.0/24] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [192.169.0.0/16] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [192.88.100.0/22] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [198.20.0.0/14] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [198.51.101.0/24] | All Connections |
| vsi2-ky[10.240.20.4] | Public Internet [203.0.114.0/23] | All Connections |
| vsi2-ky[10.240.20.4] | vsi1-ky[10.240.10.4] | All Connections * |
| vsi3a-ky[10.240.30.5] | vsi1-ky[10.240.10.4] | All Connections * |
| vsi3a-ky[10.240.30.5] | vsi3b-ky[10.240.30.6] | All Connections |
| vsi3a-ky[10.240.30.5] | vsi3c-ky[10.240.30.4] | All Connections |
| vsi3b-ky[10.240.30.6] | vsi1-ky[10.240.10.4] | All Connections * |
| vsi3b-ky[10.240.30.6] | vsi3a-ky[10.240.30.5] | All Connections |
| vsi3b-ky[10.240.30.6] | vsi3c-ky[10.240.30.4] | All Connections |
| vsi3c-ky[10.240.30.4] | vsi1-ky[10.240.10.4] | All Connections * |
| vsi3c-ky[10.240.30.4] | vsi3a-ky[10.240.30.5] | All Connections |
| vsi3c-ky[10.240.30.4] | vsi3b-ky[10.240.30.6] | All Connections |

* connections that are limited to unidirectional flow only
