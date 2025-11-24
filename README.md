> [!WARNING]  
> This repo is no longer being maintained

# vpc-network-config-analyzer

## About vpc-network-config-analyzer
This repo contains packages and a CLI for analyzing the network connectivity of a VPC, as specified by various VPC resources.
The full list of supported resources is available [here](docs/supported_resources.md).


## Usage
Run the `vpcanalyzer` CLI tool with one of the following commands.
* `vpcanalyzer report` - provides a detailed report/diagram of VPC connectivity, as implied by the given VPC configuration. [Details](docs/vpcanalyzer_report.md).
* `vpcanalyzer diff` - lists changes in connectivity (modified, added and removed connections) between two VPC configurations. [Details](docs/vpcanalyzer_diff.md).
* `vpcanalyzer explain` - explains how the given VPC configuration affects connectivity between two endpoints. [Details](docs/vpcanalyzer_explain.md).
* `vpcanalyzer lint` - provides a detailed report of potential issues in the given VPC configuration. [Details](docs/vpcanalyzer_lint.md).


### Global options
```
  -c, --config stringArray      file paths to input VPC configs, can pass multiple config files
      --dump-resources string   file path to store resources collected from the cloud provider
  -f, --filename string         file path to store results
  -h, --help                    help for vpcanalyzer
  -o, --output string           output format; must be one of [json, txt, md, drawio, arch_drawio, svg, arch_svg, html, arch_html]
  -p, --provider string         collect resources from an account in this cloud provider
  -q, --quiet                   runs quietly, reports only severe errors and results
  -r, --region stringArray      cloud region from which to collect resources, can pass multiple regions
      --resource-group string   resource group id or name from which to collect resources
  -v, --verbose                 runs with more informative messages printed to log
      --version                 version for vpcanalyzer
      --vpc string              CRN of the VPC to analyze
```

### Providing VPC configuration
A VPC configuration must be provided, in one of two ways. Either the `--provider` flag is used, in which case the VPC configuration will be extracted directly from a given account, or a configuration object is provided by the user using the `--config` option. A configuration object can be independently produced by the [`cloud-resource-collector`](https://github.com/np-guard/cloud-resource-collector).

### Output formats
Output format is set using the `--output` flag. The following formats are available for the `vpcanalyzer report` command. Other commands may not support all formats.
* `txt` - a human readable text output
* `json` - a machine readable JSON output
* `md` - markdown format
* `drawio` - a [drawio](http://draw.io) diagram showing VPC elements and their connectivity
* `arch_drawio` - a [drawio](http://draw.io) diagram showing VPC elements without their connectivity
* `svg` - an [SVG](https://en.wikipedia.org/wiki/SVG) diagram showing VPC elements and their connectivity
* `arch_svg` - an [SVG](https://en.wikipedia.org/wiki/SVG) diagram showing VPC elements without their connectivity
* `html` - an interactive html page showing a diagram of the VPC elements and their connectivity. Double clicking en element
filters out unconnected elements. Clicking a source elements, then a destination element, will show detailed information about
their connectivity at the bottom of the page.
* `arch_html` - an html page showing only the VPC elements

Output can be saved to a file using the `--filename` flag.

Example `html` output is available [here](docs/small_example.html) and [here](docs/lb_example.html) (should be downloaded to view in browser).\
Example screenshot of `html` output file is available [here](docs/html-screenshot-example.png).

## Build the project

Make sure you have golang 1.22+ on your platform

```commandline
git clone git@github.com:np-guard/vpc-network-config-analyzer.git
cd vpc-network-config-analyzer
make mod 
make build
```

Test your build by running `./bin/vpcanalyzer -h`.
