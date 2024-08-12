## vpcanalyzer report

Report VPC connectivity as implied by the given cloud configuration

### Synopsis

Provide a detailed report/diagram of allowed VPC connectivity, as implied by the given cloud configuration.

Run `vpcanalyzer report` with one of the following subcommands.
* **`vpcanalyzer report endpoints`** - Each output line is of the form: `src => dst : connection` , where each of `src` and `dst` is either a VPC endpoint (instance network interface) or an external CIDR, and `connection` is the set of allowed protocols and their relevant connection attributes (e.g., allowed source ports and/or destination ports for TCP/UDP).
* **`vpcanalyzer report subnets`** - Each output line is of the form: `src => dst : connection` , where each of `src` and `dst` is either a VPC subnet or an external CIDR, and `connection` is as explained for `vpcanalyzer report endpoints`.
* **`vpcanalyzer report single-subnet`** - The output consists of sections; one section per subnet (section header is the subnet's CIDR block). Each section consists of two sub-sections: `ingressConnectivity` and `egressConnectivity`. These sections detail the allowed connectivity to/from the subnet, as configured by the subnet's NACL resource.
* **`vpcanalyzer report routing`** - The output is the expected routing path between given source and destination endpoints, considering only VPC routing resources.

### Options

```
  -g, --grouping   whether to group together endpoints sharing the same connectivity
  -h, --help       help for report
```

### Options inherited from parent commands

```
  -c, --config stringArray      file paths to input VPC configs, can pass multiple config files
      --dump-resources string   file path to store resources collected from the cloud provider
  -f, --filename string         file path to store results
  -o, --output string           output format; must be one of [json, txt, md, drawio, arch_drawio, svg, arch_svg, html, arch_html]
  -p, --provider string         collect resources from an account in this cloud provider
  -q, --quiet                   runs quietly, reports only severe errors and results
  -r, --region stringArray      cloud region from which to collect resources, can pass multiple regions
      --resource-group string   resource group id or name from which to collect resources
  -v, --verbose                 runs with more informative messages printed to log
      --vpc string              CRN of the VPC to analyze
```

### Examples
Running
```shell
vpcanalyzer report endpoints -q -g -c pkg/ibmvpc/examples/input/input_sg_testing1_new.json
```
provides this output:
```
Endpoint connectivity for VPC test-vpc1-ky
Public Internet 147.235.219.206/32 => vsi2-ky[10.240.20.4] : protocol: TCP dst-ports: 22
db-endpoint-gateway-ky[10.240.30.6],vsi3a-ky[10.240.30.5],vsi3b-ky[10.240.30.4] => db-endpoint-gateway-ky[10.240.30.6],vsi3a-ky[10.240.30.5] : All Connections
db-endpoint-gateway-ky[10.240.30.6],vsi3a-ky[10.240.30.5],vsi3b-ky[10.240.30.4] => vsi1-ky[10.240.10.4] : All Connections
vsi1-ky[10.240.10.4] => Public Internet 142.0.0.0/7 : protocol: ICMP
vsi1-ky[10.240.10.4] => Public Internet 161.26.0.0/16 : protocol: UDP
vsi2-ky[10.240.20.4] => Public Internet 142.0.0.0/8 : protocol: ICMP
vsi2-ky[10.240.20.4] => vsi1-ky[10.240.10.4] : All Connections
vsi2-ky[10.240.20.4] => vsi3b-ky[10.240.30.4] : protocol: TCP
vsi3b-ky[10.240.30.4] => vsi2-ky[10.240.20.4] : protocol: TCP
```

***

Running
```shell
vpcanalyzer report subnets -q -g -o md -c pkg/ibmvpc/examples/input/input_sg_testing1_new.json
```
provides this output:

#### Subnet connectivity for VPC test-vpc1-ky
| src | dst | conn |
|-----|-----|------|
| subnet1-ky | Public Internet (all ranges) | All Connections |
| subnet1-ky,subnet2-ky,subnet3-ky | subnet1-ky,subnet2-ky,subnet3-ky | All Connections |


Running
```shell
vpcanalyzer report routing -c pkg/ibmvpc/examples/input/input_hub_n_spoke_1.json --src 10.1.0.4 --dst 192.168.0.4
```
Provides this output:
```
path for src 10.1.0.4, dst 192.168.0.4:
NetworkInterface - tvpc-spoke0-z1-worker[10.1.0.4] -> TGW - tvpc-tgw -> nextHop: 10.1.15.196 [origDest: 192.168.0.4]
```
