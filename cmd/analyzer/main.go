package main

import (
	"flag"
	"fmt"
	"log"
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
	case ARCHDRAWIOFormat:
		return vpcmodel.ARCHDRAWIO
	case DEBUGFormat:
		return vpcmodel.Debug
	}
	return vpcmodel.Text
}

func analysisTypeToUseCase(inArgs *InArgs) vpcmodel.OutputUseCase {
	switch *inArgs.AnalysisType {
	case allEndpoints:
		return vpcmodel.AllEndpoints
	case singleSubnet:
		return vpcmodel.SingleSubnet
	case allSubnets:
		return vpcmodel.AllSubnets
	}
	return vpcmodel.AllEndpoints
}

func analysisPerVPCConfig(c *vpcmodel.VPCConfig, inArgs *InArgs, outFile string) (*vpcmodel.VPCAnalysisOutput, error) {
	og, err := vpcmodel.NewOutputGenerator(c,
		*inArgs.Grouping,
		analysisTypeToUseCase(inArgs),
		*inArgs.OutputFormat == ARCHDRAWIOFormat)
	if err != nil {
		return nil, err
	}

	var genOutFile string
	// currently for drawio output only one vpc level is supported, and not as aggregated output of multiple vpcs
	if *inArgs.OutputFormat == ARCHDRAWIOFormat || *inArgs.OutputFormat == DRAWIOFormat {
		genOutFile = outFile
	}
	outFormat := getOutputFormat(inArgs)
	output, err := og.Generate(outFormat, genOutFile)
	if err != nil {
		return nil, fmt.Errorf("output generation error: %w", err)
	}

	return output, nil
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

	rc, err := ibmvpc.ParseResourcesFromFile(*inArgs.InputConfigFile)
	if err != nil {
		return fmt.Errorf("error parsing input vpc resources file: %w", err)
	}

	vpcConfigs, err := ibmvpc.VPCConfigsFromResources(rc, *inArgs.VPC, *inArgs.Debug)
	if err != nil {
		return fmt.Errorf("error generating cloud config from input vpc resources file: %w", err)
	}
	outFile := ""
	if inArgs.OutputFile != nil {
		outFile = *inArgs.OutputFile
	}

	outputPerVPC := make([]*vpcmodel.VPCAnalysisOutput, len(vpcConfigs))
	i := 0
	// todo: perform the required analysis
	if *inArgs.InputSecondConfigFile != "" {
		fmt.Println("2nd config file is", *inArgs.InputSecondConfigFile)
	}
	for _, vpcConfig := range vpcConfigs {
		vpcAnalysisOutput, err2 := analysisPerVPCConfig(vpcConfig, inArgs, outFile)
		if err2 != nil {
			return err2
		}
		outputPerVPC[i] = vpcAnalysisOutput
		i++
	}

	out, err := vpcmodel.AggregateVPCsOutput(outputPerVPC, getOutputFormat(inArgs), outFile)
	if err != nil {
		return err
	}
	fmt.Println(out)

	return nil
}

func main() {
	err := _main(os.Args[1:])
	if err != nil {
		log.Fatalf("%v. exiting...", err)
	}
}
