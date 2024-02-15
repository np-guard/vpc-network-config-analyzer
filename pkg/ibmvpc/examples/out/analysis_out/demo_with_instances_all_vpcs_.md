# Endpoint connectivity for VPC ky-testenv-vpc
| src | dst | conn |
|-----|-----|------|
| edge-0-instance-ky[192.168.32.4] | Public Internet (all ranges) | All Connections |
| edge-0-instance-ky[192.168.32.4] | edge-1-instance-ky[192.168.36.4] | All Connections |
| edge-0-instance-ky[192.168.32.4] | edge-2-instance-ky[192.168.40.4] | All Connections |
| edge-0-instance-ky[192.168.32.4] | private-0-instance-ky[192.168.0.4] | protocol: TCP src-ports: 443 |
| edge-0-instance-ky[192.168.32.4] | private-1-instance-ky[192.168.4.4] | protocol: TCP src-ports: 443 |
| edge-0-instance-ky[192.168.32.4] | private-2-instance-ky[192.168.8.4] | protocol: TCP src-ports: 443 |
| edge-0-instance-ky[192.168.32.4] | transit-0-instance-ky[192.168.16.4] | All Connections |
| edge-0-instance-ky[192.168.32.4] | transit-1-instance-ky[192.168.20.4] | All Connections |
| edge-0-instance-ky[192.168.32.4] | transit-2-instance-ky[192.168.24.4] | All Connections |
| edge-1-instance-ky[192.168.36.4] | Public Internet (all ranges) | All Connections |
| edge-1-instance-ky[192.168.36.4] | edge-0-instance-ky[192.168.32.4] | All Connections |
| edge-1-instance-ky[192.168.36.4] | edge-2-instance-ky[192.168.40.4] | All Connections |
| edge-1-instance-ky[192.168.36.4] | private-0-instance-ky[192.168.0.4] | protocol: TCP src-ports: 443 |
| edge-1-instance-ky[192.168.36.4] | private-1-instance-ky[192.168.4.4] | protocol: TCP src-ports: 443 |
| edge-1-instance-ky[192.168.36.4] | private-2-instance-ky[192.168.8.4] | protocol: TCP src-ports: 443 |
| edge-1-instance-ky[192.168.36.4] | transit-0-instance-ky[192.168.16.4] | All Connections |
| edge-1-instance-ky[192.168.36.4] | transit-1-instance-ky[192.168.20.4] | All Connections |
| edge-1-instance-ky[192.168.36.4] | transit-2-instance-ky[192.168.24.4] | All Connections |
| edge-2-instance-ky[192.168.40.4] | Public Internet (all ranges) | All Connections |
| edge-2-instance-ky[192.168.40.4] | edge-0-instance-ky[192.168.32.4] | All Connections |
| edge-2-instance-ky[192.168.40.4] | edge-1-instance-ky[192.168.36.4] | All Connections |
| edge-2-instance-ky[192.168.40.4] | private-0-instance-ky[192.168.0.4] | protocol: TCP src-ports: 443 |
| edge-2-instance-ky[192.168.40.4] | private-1-instance-ky[192.168.4.4] | protocol: TCP src-ports: 443 |
| edge-2-instance-ky[192.168.40.4] | private-2-instance-ky[192.168.8.4] | protocol: TCP src-ports: 443 |
| edge-2-instance-ky[192.168.40.4] | transit-0-instance-ky[192.168.16.4] | All Connections |
| edge-2-instance-ky[192.168.40.4] | transit-1-instance-ky[192.168.20.4] | All Connections |
| edge-2-instance-ky[192.168.40.4] | transit-2-instance-ky[192.168.24.4] | All Connections |
| private-0-instance-ky[192.168.0.4] | edge-0-instance-ky[192.168.32.4] | protocol: TCP dst-ports: 443 |
| private-0-instance-ky[192.168.0.4] | edge-1-instance-ky[192.168.36.4] | protocol: TCP dst-ports: 443 |
| private-0-instance-ky[192.168.0.4] | edge-2-instance-ky[192.168.40.4] | protocol: TCP dst-ports: 443 |
| private-0-instance-ky[192.168.0.4] | private-1-instance-ky[192.168.4.4] | protocol: TCP src-ports: 443 dst-ports: 443 |
| private-0-instance-ky[192.168.0.4] | private-2-instance-ky[192.168.8.4] | protocol: TCP src-ports: 443 dst-ports: 443 |
| private-0-instance-ky[192.168.0.4] | transit-0-instance-ky[192.168.16.4] | protocol: TCP dst-ports: 443 |
| private-0-instance-ky[192.168.0.4] | transit-1-instance-ky[192.168.20.4] | protocol: TCP dst-ports: 443 |
| private-0-instance-ky[192.168.0.4] | transit-2-instance-ky[192.168.24.4] | protocol: TCP dst-ports: 443 |
| private-1-instance-ky[192.168.4.4] | edge-0-instance-ky[192.168.32.4] | protocol: TCP dst-ports: 443 |
| private-1-instance-ky[192.168.4.4] | edge-1-instance-ky[192.168.36.4] | protocol: TCP dst-ports: 443 |
| private-1-instance-ky[192.168.4.4] | edge-2-instance-ky[192.168.40.4] | protocol: TCP dst-ports: 443 |
| private-1-instance-ky[192.168.4.4] | private-0-instance-ky[192.168.0.4] | protocol: TCP src-ports: 443 dst-ports: 443 |
| private-1-instance-ky[192.168.4.4] | private-2-instance-ky[192.168.8.4] | protocol: TCP src-ports: 443 dst-ports: 443 |
| private-1-instance-ky[192.168.4.4] | transit-0-instance-ky[192.168.16.4] | protocol: TCP dst-ports: 443 |
| private-1-instance-ky[192.168.4.4] | transit-1-instance-ky[192.168.20.4] | protocol: TCP dst-ports: 443 |
| private-1-instance-ky[192.168.4.4] | transit-2-instance-ky[192.168.24.4] | protocol: TCP dst-ports: 443 |
| private-2-instance-ky[192.168.8.4] | edge-0-instance-ky[192.168.32.4] | protocol: TCP dst-ports: 443 |
| private-2-instance-ky[192.168.8.4] | edge-1-instance-ky[192.168.36.4] | protocol: TCP dst-ports: 443 |
| private-2-instance-ky[192.168.8.4] | edge-2-instance-ky[192.168.40.4] | protocol: TCP dst-ports: 443 |
| private-2-instance-ky[192.168.8.4] | private-0-instance-ky[192.168.0.4] | protocol: TCP src-ports: 443 dst-ports: 443 |
| private-2-instance-ky[192.168.8.4] | private-1-instance-ky[192.168.4.4] | protocol: TCP src-ports: 443 dst-ports: 443 |
| private-2-instance-ky[192.168.8.4] | transit-0-instance-ky[192.168.16.4] | protocol: TCP dst-ports: 443 |
| private-2-instance-ky[192.168.8.4] | transit-1-instance-ky[192.168.20.4] | protocol: TCP dst-ports: 443 |
| private-2-instance-ky[192.168.8.4] | transit-2-instance-ky[192.168.24.4] | protocol: TCP dst-ports: 443 |
| transit-0-instance-ky[192.168.16.4] | edge-0-instance-ky[192.168.32.4] | All Connections |
| transit-0-instance-ky[192.168.16.4] | edge-1-instance-ky[192.168.36.4] | All Connections |
| transit-0-instance-ky[192.168.16.4] | edge-2-instance-ky[192.168.40.4] | All Connections |
| transit-0-instance-ky[192.168.16.4] | private-0-instance-ky[192.168.0.4] | protocol: TCP src-ports: 443 |
| transit-0-instance-ky[192.168.16.4] | private-1-instance-ky[192.168.4.4] | protocol: TCP src-ports: 443 |
| transit-0-instance-ky[192.168.16.4] | private-2-instance-ky[192.168.8.4] | protocol: TCP src-ports: 443 |
| transit-0-instance-ky[192.168.16.4] | transit-1-instance-ky[192.168.20.4] | All Connections |
| transit-0-instance-ky[192.168.16.4] | transit-2-instance-ky[192.168.24.4] | All Connections |
| transit-1-instance-ky[192.168.20.4] | edge-0-instance-ky[192.168.32.4] | All Connections |
| transit-1-instance-ky[192.168.20.4] | edge-1-instance-ky[192.168.36.4] | All Connections |
| transit-1-instance-ky[192.168.20.4] | edge-2-instance-ky[192.168.40.4] | All Connections |
| transit-1-instance-ky[192.168.20.4] | private-0-instance-ky[192.168.0.4] | protocol: TCP src-ports: 443 |
| transit-1-instance-ky[192.168.20.4] | private-1-instance-ky[192.168.4.4] | protocol: TCP src-ports: 443 |
| transit-1-instance-ky[192.168.20.4] | private-2-instance-ky[192.168.8.4] | protocol: TCP src-ports: 443 |
| transit-1-instance-ky[192.168.20.4] | transit-0-instance-ky[192.168.16.4] | All Connections |
| transit-1-instance-ky[192.168.20.4] | transit-2-instance-ky[192.168.24.4] | All Connections |
| transit-2-instance-ky[192.168.24.4] | edge-0-instance-ky[192.168.32.4] | All Connections |
| transit-2-instance-ky[192.168.24.4] | edge-1-instance-ky[192.168.36.4] | All Connections |
| transit-2-instance-ky[192.168.24.4] | edge-2-instance-ky[192.168.40.4] | All Connections |
| transit-2-instance-ky[192.168.24.4] | private-0-instance-ky[192.168.0.4] | protocol: TCP src-ports: 443 |
| transit-2-instance-ky[192.168.24.4] | private-1-instance-ky[192.168.4.4] | protocol: TCP src-ports: 443 |
| transit-2-instance-ky[192.168.24.4] | private-2-instance-ky[192.168.8.4] | protocol: TCP src-ports: 443 |
| transit-2-instance-ky[192.168.24.4] | transit-0-instance-ky[192.168.16.4] | All Connections |
| transit-2-instance-ky[192.168.24.4] | transit-1-instance-ky[192.168.20.4] | All Connections |
