package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/ibmvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const (
	ParsingErr       = "error parsing arguments:"
	OutGenerationErr = "output generation error:"
	InGenerationErr  = "error generating cloud config from input vpc resources file:"
	ErrorFormat      = "%s %w"
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
	case allSubnetsDiff:
		return vpcmodel.AllSubnetsDiff
	}
	return vpcmodel.AllEndpoints
}

func analysisPerVPCConfig(c *vpcmodel.VPCConfig, inArgs *InArgs, outFile string) (*vpcmodel.VPCAnalysisOutput, error) {
	og, err := vpcmodel.NewOutputGenerator(c, nil,
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
		return nil, fmt.Errorf(ErrorFormat, OutGenerationErr, err)
	}

	return output, nil
}

func analysisDiffVPCConfig(c1, c2 *vpcmodel.VPCConfig, inArgs *InArgs, outFile string) (*vpcmodel.VPCAnalysisOutput, error) {
	og, err := vpcmodel.NewOutputGenerator(c1, c2,
		*inArgs.Grouping,
		analysisTypeToUseCase(inArgs),
		false)
	if err != nil {
		return nil, err
	}

	var analysisOut *vpcmodel.VPCAnalysisOutput
	outFormat := getOutputFormat(inArgs)
	analysisOut, err = og.Generate(outFormat, outFile)
	if err != nil {
		return nil, fmt.Errorf(ErrorFormat, OutGenerationErr, err)
	}

	return analysisOut, nil
}

// The actual main function
// Takes command-line flags and returns an error rather than exiting, so it can be more easily used in testing
func _main(cmdlineArgs []string) error {
	inArgs, err := ParseInArgs(cmdlineArgs)
	if err == flag.ErrHelp {
		return nil
	}
	if err != nil {
		return fmt.Errorf(ErrorFormat, ParsingErr, err)
	}

	rc, err := ibmvpc.ParseResourcesFromFile(*inArgs.InputConfigFile)
	if err != nil {
		return fmt.Errorf("error parsing input vpc resources file: %w", err)
	}

	vpcConfigs, err := ibmvpc.VPCConfigsFromResources(rc, *inArgs.VPC, *inArgs.Debug)
	if err != nil {
		return fmt.Errorf(ErrorFormat, InGenerationErr, err)
	}

	outFile := ""
	if inArgs.OutputFile != nil {
		outFile = *inArgs.OutputFile
	}

	diffAnalysis := *inArgs.AnalysisType == allEndpointsDiff || *inArgs.AnalysisType == allSubnetsDiff
	if !diffAnalysis {
		outputPerVPC := make([]*vpcmodel.VPCAnalysisOutput, len(vpcConfigs))
		i := 0
		for _, vpcConfig := range vpcConfigs {
			vpcAnalysisOutput, err2 := analysisPerVPCConfig(vpcConfig, inArgs, outFile)
			if err2 != nil {
				return err2
			}
			outputPerVPC[i] = vpcAnalysisOutput
			i++
		}

		var out string
		out, err = vpcmodel.AggregateVPCsOutput(outputPerVPC, getOutputFormat(inArgs), outFile)
		if err != nil {
			return err
		}
		fmt.Println(out)
	} else {
		// Diff analysis
		// ToDo SM: for diff analysis assume 2 configs only, the 2nd given through vpc-config-second
		var rc2ndForDiff *ibmvpc.ResourcesContainer
		rc2ndForDiff, err = ibmvpc.ParseResourcesFromFile(*inArgs.InputSecondConfigFile)
		if err != nil {
			return fmt.Errorf(ErrorFormat, ParsingErr, err)
		}
		vpc2ndConfigs, err := ibmvpc.VPCConfigsFromResources(rc2ndForDiff, *inArgs.VPC, *inArgs.Debug)
		if err != nil {
			return fmt.Errorf(ErrorFormat, InGenerationErr, err)
		}
		// For diff analysis each vpcConfigs have a single element
		c1 := getFirstCfg(vpcConfigs)
		c2 := getFirstCfg(vpc2ndConfigs)
		analysisOutput, err2 := analysisDiffVPCConfig(c1, c2, inArgs, outFile)
		if err2 != nil {
			return err2
		}
		fmt.Println(analysisOutput.Output)
	}
	return nil
}

func getFirstCfg(vpcConfigs map[string]*vpcmodel.VPCConfig) *vpcmodel.VPCConfig {
	for _, vpcConfig := range vpcConfigs {
		return vpcConfig
	}
	return nil
}

func main() {
	err := _main(os.Args[1:])
	if err != nil {
		log.Fatalf("%v. exiting...", err)
	}
}
