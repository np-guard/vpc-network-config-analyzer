## vpcanalyzer diff
Diff connectivity postures as implied by two VPC configs

### Synopsis
List changes in connectivity (modified, added and removed connections) between two VPC configurations. The first configuration is specified using the `--vpc-config` option, or alternatively using the `--provider` option. The second configuration is specified using the `--vpc-config-second` option.

Each output line describes a difference between the configurations and contains the following fields.
* `diff-type` - whether the described connection was added, removed, or changed from the first config to the second.
* `src` and `dst` - connection source and connection destination. These may be either network interfaces or subnets, depending on the subcommand (see below).
* `config1` and `config2` - the allowed connections in the 1st and 2nd configuration, respectively. `no connection` is a possible value in either field.
* `diff-info` - whether `src` or `dst` were added or removed from the first config to the second.

Run `vpcanalyzer diff` with one of the following subcommands, affecting report granularity.
* **`vpcanalyzer diff endpoints`** - diff connectivity in the level of VPC endpoints (network interfaces).
* **`vpcanalyzer diff subnets`** - diff connectivity in the level of subnets.

### Options
```
  -h, --help                       help for diff
      --vpc-config-second string   file path to the 2nd input config
```

### Options inherited from parent commands
```
      --debug                    runs in debug mode
      --dump-resources string    file path to store resources collected from the cloud provider
  -o, --format string            output format; must be one of [json, txt, md, drawio, arch_drawio, svg, arch_svg, html, arch_html, debug]
      --output-file string       file path to store results
  -p, --provider string          collect resources from an account in this cloud provider
  -q, --quiet                    runs quietly, reports only severe errors and results
  -r, --region stringArray       cloud region from which to collect resources, can pass multiple regions
      --resource-group string    resource group id or name from which to collect resources
  -v, --verbose                  runs with more informative messages printed to log
      --vpc string               CRN of the VPC to analyze
  -c, --vpc-config stringArray   file paths to input configs, can pass multiple config files
```
### Example
```
> vpcanalyzer diff endpoints -q -c pkg/ibmvpc/examples/input/input_sg_testing1_new.json --vpc-config-second pkg/ibmvpc/examples/input/input_sg_testing1_new_2SGs.json
Connectivity diff between VPC test-vpc1-ky and VPC test-vpc1-ky
diff-type: added, source: vsi1-ky[10.240.10.4], destination: Public Internet 1.0.0.0-9.255.255.255,11.0.0.0-100.63.255.255,100.128.0.0-126.255.255.255,128.0.0.0-141.255.255.255,144.0.0.0-161.25.255.255,161.27.0.0-169.253.255.255,169.255.0.0-172.15.255.255,172.32.0.0-191.255.255.255,192.0.1.0/24,192.0.3.0-192.88.98.255,192.88.100.0-192.167.255.255,192.169.0.0-198.17.255.255,198.20.0.0-198.51.99.255,198.51.101.0-203.0.112.255,203.0.114.0-223.255.255.255, config1: No Connections, config2: All Connections
diff-type: added, source: vsi1-ky[10.240.10.4], destination: vsi2-ky[10.240.20.4], config1: No Connections, config2: All Connections
diff-type: added, source: vsi1-ky[10.240.10.4], destination: vsi3b-ky[10.240.30.4], config1: No Connections, config2: All Connections
diff-type: changed, source: vsi1-ky[10.240.10.4], destination: Public Internet 142.0.0.0/7, config1: protocol: ICMP, config2: All Connections
diff-type: changed, source: vsi1-ky[10.240.10.4], destination: Public Internet 161.26.0.0/16, config1: protocol: UDP, config2: All Connections
```
