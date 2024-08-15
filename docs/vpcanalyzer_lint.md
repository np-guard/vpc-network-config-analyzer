## vpcanalyzer lint

provides a detailed report of potential issues in the given VPC configuration

### Synopsis

The following linters are supported:

| Name                            | Description                                                                |
|---------------------------------|----------------------------------------------------------------------------|
| **nacl-split-subnet**           | Network ACLs implying different connectivity for endpoints inside a subnet | 
| **sg-split-subnet**             | SGs implying different connectivity for endpoints inside a subnet          |  
| **subnet-cidr-overlap**         | Overlapping subnet address spaces                                          |  
| **nacl-unattached**             | Network ACL not applied to any resources                                   |  
| **sg-unattached**               | SG not applied to any resources                                            |  
| **sg-rule-cidr-out-of-range**   | Security group rules referencing CIDRs outside of the VPC address space    |
| **nacl-rule-cidr-out-of-range** | Network ACL rules referencing CIDRs outside of the VPC address space       |
| **tcp-response-blocked**        | Blocked TCP response                                                       |
| **nacl-rule-shadowed**          | Network ACL rules shadowed by higher priority rules                        |
| **sg-rule-implied**             | Security group rules implied by other rules                                |


```
vpcanalyzer explain [flags]
```

### Options

```
      --disable strings         disable specific linters, specified as linter names separated by comma.
                                linters: sg-rule-implied,sg-split-subnet,subnet-cidr-overlap,nacl-unattached,sg-unattached,nacl-rule-cidr-out-of-range,nacl-split-subnet,sg-rule-cidr-out-of-range,tcp-response-blocked,nacl-rule-shadowed    
      --enable strings          enable specific linters, specified as linter names separated by comma.
                                linters: sg-rule-implied,sg-split-subnet,subnet-cidr-overlap,nacl-unattached,sg-unattached,nacl-rule-cidr-out-of-range,nacl-split-subnet,sg-rule-cidr-out-of-range,tcp-response-blocked,nacl-rule-shadowed    
      --print-all               print all findings (do not limit findings of each linter to 3)

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

### Example
```
> go run analyzer lint -q -c input/input_tgw_larger_example.json
"Blocked TCP response" issues:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
In the connection from "test-vpc3-ky/vsi31-ky[10.240.31.4]" to "test-vpc1-ky/vsi11-ky[10.240.11.4]" TCP response is blocked
In the connection from "test-vpc3-ky/vsi31-ky[10.240.31.4]" to "test-vpc1-ky/vsi12-ky[10.240.12.4]" TCP response is blocked
________________________________________________________________________________________________________________________________________________________________________________________________________

"NACL not applied to any resources" issues:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
In VPC "test-vpc0-ky", network ACL "stimulus-surpass-backup-museum" has no resources attached to it
In VPC "test-vpc1-ky", network ACL "unsaid-numerate-alto-dried" has no resources attached to it
In VPC "test-vpc2-ky", network ACL "sixtieth-resurrect-pledge-wince" has no resources attached to it
... (3 more)

________________________________________________________________________________________________________________________________________________________________________________________________________

"Overlapping subnet address spaces" issues:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
VPC "test-vpc2-ky"'s subnet "subnet21-ky" [10.240.64.0/24] and VPC "zn-vpc2"'s subnet "zn-vpc2-net1" [10.240.64.0/24] overlap
________________________________________________________________________________________________________________________________________________________________________________________________________

"SG not applied to any resources" issues:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
In VPC "test-vpc0-ky", security group "relenting-sixfold-moisturize-emcee" has no resources attached to it
"rules of network ACLs that are shadowed by higher priority rules" issues:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
In VPC "test-vpc0-ky", network ACL "acl2-ky" rule [2] is shadowed by higher priority rules
        Rule details: index: 2, direction: outbound , src: 10.240.2.0/24 , dst: 10.240.1.0/24, conn: all, action: allow
                Shadowing rules:
                        index: 0, direction: outbound , src: 10.240.2.0/24 , dst: 10.240.0.0/16, conn: all, action: deny
                        index: 1, direction: outbound , src: 10.240.2.0/24 , dst: 0.0.0.0/0, conn: all, action: allow

In VPC "test-vpc0-ky", network ACL "acl2-ky" rule [5] is shadowed by higher priority rules
        Rule details: index: 5, direction: inbound , src: 10.240.1.0/24 , dst: 10.240.2.0/24, conn: all, action: allow
                Shadowing rules:
                        index: 3, direction: inbound , src: 10.240.0.0/16 , dst: 10.240.2.0/24, conn: all, action: deny
                        index: 4, direction: inbound , src: 0.0.0.0/0 , dst: 10.240.2.0/24, conn: all, action: allow

------------------------------------------------------------------------------------------------------------------------
```
