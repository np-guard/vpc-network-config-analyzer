package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/ibmvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func getOutputFormat(inArgs *InArgs) vpcmodel.OutFormat {
	switch *inArgs.OutputFormat {
	case TEXTFormat:
		return vpcmodel.Text
	case MDFormat:
		return vpcmodel.MD
	case JSONFormat:
		return vpcmodel.JSON
	case DRAWIOFormat:
		return vpcmodel.DRAWIO
	}
	return vpcmodel.Text
}

// The actual main function
// Takes command-line flags and returns an error rather than exiting, so it can be more easily used in testing
func _main(cmdlineArgs []string) error {
	inArgs, err := ParseInArgs(cmdlineArgs)
	if err == flag.ErrHelp {
		return nil
	}
	if err != nil {
		return fmt.Errorf("error parsing arguments: %w", err)
	}

	rc, err := ibmvpc.ParseResourrcesFromFile(*inArgs.InputConfigFile)
	if err != nil {
		return fmt.Errorf("error parsing input vpc resources file: %w", err)
	}

	cloudConfig, err := ibmvpc.NewCloudConfig(rc)
	if err != nil {
		return fmt.Errorf("error generating cloud config from input vpc resources file: %w", err)
	}

	var output string
	switch *inArgs.AnalysisType {
	case VsiLevel:
		vpcConn := cloudConfig.GetVPCNetworkConnectivity()
		// TODO: extend output generator to support other analysis types
		o := vpcmodel.NewOutputGenerator(cloudConfig, vpcConn)
		outFile := ""
		if inArgs.OutputFile != nil {
			outFile = *inArgs.OutputFile
		}
		outFormat := getOutputFormat(inArgs)
		o.SetOutputFile(outFile, outFormat)

		output, err = o.Generate(outFormat)
		if err != nil {
			return fmt.Errorf("output generation error: %w", err)
		}

	case SubnetsLevel:
		vpcConn, err := cloudConfig.GetSubnetsConnectivity(true)
		if err != nil {
			return fmt.Errorf("analysis error: %w", err)
		}
		output = vpcConn.String()
		// TODO: save to file if required

	case DebugSubnet:
		output = cloudConfig.GetConnectivityOutputPerEachSubnetSeparately()
		// TODO: save to file if required

	default:
		return fmt.Errorf("unexpected analysis type: %s", *inArgs.AnalysisType)
	}
	// print to stdout as well
	fmt.Println(output)

	return nil
}

func main() {
	err := _main(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v. exiting...", err)
		os.Exit(1)
	}
}
