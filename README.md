# vpc-network-config-analyzer

## About vpc-network-config-analyzer
This repo contains packages and a CLI for analyzing the network connectivity of a VPC as specified by various VPC resources.


## Usage
```
$ ./bin/vpcanalyzer -h
Usage of vpc-network-config-analyzer:
  -analysis-type string
        Supported analysis types:
        * all_endpoints  - supported with: txt, md, json, drawio, arch_drawio, debug
        * all_subnets  - supported with: txt, md, json, drawio, arch_drawio
        * single_subnet  - supported with: txt
        * diff_all_endpoints  - supported with: txt, md
        * diff_all_subnets  - supported with: txt, md
        * explain  - supported with: txt, debug
         (default "all_endpoints")
  -debug
        Run in debug mode
  -dst string
        Destination endpoint for explanation; can be specified as a VSI name/CRN or an internal/external IP-address/CIDR
  -dst-max-port int
        Maximum destination port for connection description (default 65535)
  -dst-min-port int
        Minimum destination port for connection description (default 1)
  -dump-resources string
        File path to store resources collected from the cloud provider
  -format string
        Output format; must be one of:
        txt, md, json, drawio, arch_drawio, debug (default "txt")
  -grouping
        Whether to group together src/dst entries with identical connectivity
        Does not support single_subnet, diff_all_endpoints and diff_all_subnets analysis-types and json output format
  -output-file string
        File path to store results
  -protocol string
        Protocol for connection description
  -provider string
        Collect resources from an account in this cloud provider
  -region value
        Cloud region from which to collect resources
  -resource-group string
        Resource group id or name from which to collect resources
  -src string
        Source endpoint for explanation; can be specified as a VSI name/CRN or an internal/external IP-address/CIDR
  -src-max-port int
        Maximum source port for connection description (default 65535)
  -src-min-port int
        Minimum source port for connection description (default 1)
  -version
        Prints the release version number
  -vpc string
        CRN of the VPC to analyze
  -vpc-config string
        Required. File path to input config
  -vpc-config-second string
        File path to the 2nd input config; relevant only for analysis-type diff_all_endpoints and for diff_all_subnets

  
```

### Input config files
An input config file should be a `JSON` file produced by the [`cloud-resource-collector`](https://github.com/np-guard/cloud-resource-collector)

## Understanding the output

### `all_endpoints` analysis type
Each output line is of the form: `src => dst : connection` , where each of `src` and `dst` is either a VPC endpoint (instance network interface) or an external CIDR, and `connection` is the set of allowed protocols and their relevant connection attributes (e.g., allowed source ports and/or destination ports for TCP/UDP).

### `all_subnets` analysis type 
Each output line is of the form: `src => dst : connection` , where each of `src` and `dst` is either a VPC subnet or an external CIDR, and `connection` is as explained for `all_endpoints`.

### `single_subnet` analysis type 
The output consists of sections; one section per subnet (section header is the subnet's CIDR block). Each section consists of two sub-sections: `ingressConnectivity` and `egressConnectivity`. These sections detail the allowed connectivity to/from the subnet, as configured by the subnet's NACL resource.

### `diff_all_endpoints` analysis type
Each output line describes a difference between the configurations and contains the following. `diff-type`: whether the line described an added, removed, or changed connection between the 1st config to the 2nd; `src` and `dst` as in analysis `all_endpoints` above; `config1` and `config2` describes the connections in the 1st and 2nd configurations, possibly by `no connection`. Finally, `vsis-diff-info` describes the differences in the vsis existence between the two configurations  

### `diff_all_subnets` analysis type
The output is very similar to the one in `diff_all_endpoints` with `vsis` replaced by `subnets`: `src` and `dst` are as in analysis `all_subnets` and the last column is `subnets-diff-info` 

### `explain` analysis type
Answers the query regarding `src`, `dst` and the provided `protocol` and `port` cli options. 
If the queried connection or a subset of it is allowed, then a list of the enabling resources is provided. Examples for enabling resources:  public-gw, security group, and network ACL.
If the required connection is blocked, then details of the blocking resources is provided. For example, a missing FIP could be blocking resource for connectivity to public Internet, or NACL rule could block certain direction ingress/egress. 
In debug output format the list of the relevant (allow/deny) rules is also provided.
      

## Build the project

Make sure you have golang 1.21+ on your platform

```commandline
git clone git@github.com:np-guard/vpc-network-config-analyzer.git
cd vpc-network-config-analyzer
make mod 
make build
```

Test your build by running `./bin/vpcanalyzer -h`.



