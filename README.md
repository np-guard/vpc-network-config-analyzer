# vpc-network-config-analyzer

## About vpc-network-config-analyzer
This repo contains a CLI for analyzing the network connectivity of a VPC as specified by various VPC resources.


## Usage
```
$ ./bin/vpcanalyzer -h
Usage of vpc-network-config-analyzer:
  -analysis-type string
        supported analysis types: all_endpoints,all_subnets,single_subnet (default "all_endpoints")
  -format string
        output format; must be one of json,txt,md,drawio (default "txt")
  -grouping
        grouping: whether to apply grouping of connectivity lines
  -output-file string
        file path to store results
  -vpc-config string
        file path to input config

```

### Input config file
The input config file should be the `json` file produced by the [`cloud-resource-collector`](https://github.com/np-guard/cloud-resource-collector)

## Understanding the output

### all_endpoints analysis type
Each output line is of the form: `src => dst : connection` , where `src`,`dst` are either VPC endpoints (instance network interface) or external CIDR, and `connection` is the set of allowed protocols and their relevant connection attributes (e.g. source ports or destination ports for TCP/UDP).

### all_subnets analysis type 
Each output line is of the form: `src => dst : connection` , where `src`,`dst` are either VPC subnets or external CIDR, and `connection` is as explained above.

### single_subnet analysis type 
The output consists of sections per each subnet (section header is the subnet CIDR block). Each section consists of two sub-sections: ingressConnectivity and egressConnectivity. These sections detail the allowed connectivity to/from the subnet, as configured by the subnet's NACL resource.

## Build the project

Make sure you have golang 1.19+ on your platform

```commandline
git clone git@github.com:np-guard/vpc-network-config-analyzer.git
cd vpc-network-config-analyzer
make mod 
make build
```

Test your build by running `./bin/vpcanalyzer -h`.



