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
	}
	return vpcmodel.Text
}

func analysisTypeToUseCase(inArgs *InArgs) vpcmodel.OutputUseCase {
	switch *inArgs.AnalysisType {
	case VsiLevel:
		return vpcmodel.VsiLevel
	case DebugSubnet:
		return vpcmodel.DebugSubnet
	case SubnetsLevel:
		return vpcmodel.SubnetsLevel
	}
	return vpcmodel.VsiLevel
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

	og, err := vpcmodel.NewOutputGenerator(cloudConfig, *inArgs.Grouping, analysisTypeToUseCase(inArgs))
	if err != nil {
		return err
	}
	outFile := ""
	if inArgs.OutputFile != nil {
		outFile = *inArgs.OutputFile
	}
	outFormat := getOutputFormat(inArgs)

	output, err := og.Generate(outFormat, outFile)
	if err != nil {
		return fmt.Errorf("output generation error: %w", err)
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
