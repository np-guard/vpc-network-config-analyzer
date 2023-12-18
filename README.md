# vpc-network-config-analyzer

## About vpc-network-config-analyzer
This repo contains packages and a CLI for analyzing the network connectivity of a VPC as specified by various VPC resources.


## Usage
```
$ ./bin/vpcanalyzer -h
Usage of vpc-network-config-analyzer:
  -analysis-type string
        supported analysis types: all_endpoints,all_subnets,single_subnet, diff_all_endpoints, diff_all_subnets (default "all_endpoints")
  -format string
        output format; must be one of txt,md,drawio,arch_drawio,json (default "txt")
  -grouping
        whether to group together src/dst entries with identical connectivity
  -output-file string
        file path to store results
  -vpc-config string
        file path to input config
  -vpc-config-second string
        file path to the 2nd input config; relevant only for analysis-type diff_all_endpoints and for diff_all_subnets
  -version
        prints the release version number    
```

### Input config files
An input config file should be a `JSON` file produced by the [`cloud-resource-collector`](https://github.com/np-guard/cloud-resource-collector)

## Understanding the output

### all_endpoints analysis type
Each output line is of the form: `src => dst : connection` , where each of `src` and `dst` is either a VPC endpoint (instance network interface) or an external CIDR, and `connection` is the set of allowed protocols and their relevant connection attributes (e.g., allowed source ports and/or destination ports for TCP/UDP).

### all_subnets analysis type 
Each output line is of the form: `src => dst : connection` , where each of `src` and `dst` is either a VPC subnet or an external CIDR, and `connection` is as explained for `all_endpoints`.

### single_subnet analysis type 
The output consists of sections; one section per subnet (section header is the subnet's CIDR block). Each section consists of two sub-sections: `ingressConnectivity` and `egressConnectivity`. These sections detail the allowed connectivity to/from the subnet, as configured by the subnet's NACL resource.

### diff_all_endpoints analysis type
Each output line describes a difference between the configurations and contains the following. `diff-type`: whether the line described an added, removed, or changed connection between the 1st config to the 2nd; `src` and `dst` as in analysis `all_endpoints` above; `config1` and `config2` describes the connections in the 1st and 2nd configurations, possibly by `no connection`. Finally, `vsis-diff-info` describes the differences in the vsis existence between the two configurations  

### diff_all_subnets analysis type
The output is very similar to the one in `diff_all_endpoints` with `vsis` replaced by `subnets`: `src` and `dst` are as in analysis `all_subnets` and the last column is `subnets-diff-info` 

## Build the project

Make sure you have golang 1.19+ on your platform

```commandline
git clone git@github.com:np-guard/vpc-network-config-analyzer.git
cd vpc-network-config-analyzer
make mod 
make build
```

Test your build by running `./bin/vpcanalyzer -h`.



