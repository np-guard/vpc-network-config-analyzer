## vpcanalyzer explain

Explain connectivity between two endpoints

### Synopsis

Explain how the given VPC configuration affects connectivity from `src` to `dst`, using the provided `protocol` and `port`.

If the queried connection (or a subset of it) is allowed, then a list of the enabling resources is provided.
Examples for enabling resources:  public-gateway, security group, and network ACL.

If the required connection is blocked, then details of the blocking resources is provided. For example, a missing Floating-IP may block traffic to public Internet, a Network ACL rule may block specific ingress/egress traffic.

In output format is set to `debug`, the list of the relevant (allow/deny) rules is also provided.

```
vpcanalyzer explain [flags]
```

### Options

```
      --src string         source endpoint for explanation; can be specified as a VSI name/CRN or an internal/external IP-address/CIDR;
                           VSI name can be specified as <vsi-name> or  <vpc-name>/<vsi-name>
      --dst string         destination endpoint for explanation; can be specified as a VSI name/CRN or an internal/external IP-address/CIDR;
                           VSI name can be specified as <vsi-name> or  <vpc-name>/<vsi-name>
      --protocol string    protocol for connection description
      --src-min-port int   minimum source port for connection description (default 1)
      --src-max-port int   maximum source port for connection description (default 65535)
      --dst-min-port int   minimum destination port for connection description (default 1)
      --dst-max-port int   maximum destination port for connection description (default 65535)
  -h, --help               help for explain
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
> vpcanalyzer explain -q -c pkg/ibmvpc/examples/input/input_sg_testing_default.json --src 10.240.30.6 --dst vsi2-ky -o debug
Explaining connectivity from 10.240.30.6 (db-endpoint-gateway-ky[10.240.30.6]) to vsi2-ky within test-vpc1-ky
=============================================================================================================

Allowed connections from db-endpoint-gateway-ky[10.240.30.6] to vsi2-ky[10.240.20.4]: All Connections

Path:
        db-endpoint-gateway-ky[10.240.30.6] -> security group sg3-ky -> subnet3-ky -> network ACL acl3-ky ->
        network ACL acl2-ky -> subnet2-ky -> security group sg2-ky -> vsi2-ky[10.240.20.4]


Details:
~~~~~~~~
Egress:
security group sg3-ky allows connection with the following allow rules
        index: 0, direction: outbound,  conns: protocol: all, remote: 0.0.0.0/0, local: 0.0.0.0/0
network ACL acl3-ky allows connection with the following allow rules
        index: 0, direction: outbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow

Ingress:
network ACL acl2-ky allows connection with the following allow rules
        index: 1, direction: inbound , src: 0.0.0.0/0 , dst: 0.0.0.0/0, conn: all, action: allow
security group sg2-ky allows connection with the following allow rules
        index: 1, direction: inbound,  conns: protocol: all, remote: 0.0.0.0/0, local: 0.0.0.0/0

------------------------------------------------------------------------------------------------------------------------
```
