package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/ibmvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/version"
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
		return vpcmodel.SubnetsDiff
	case allEndpointsDiff:
		return vpcmodel.EndpointsDiff
	}
	return vpcmodel.AllEndpoints
}

func analysisVPCConfigs(c1, c2 map[string]*vpcmodel.VPCConfig, inArgs *InArgs, outFile string) (string, error) {
	og, err := vpcmodel.NewOutputGenerator(c1, c2,
		*inArgs.Grouping,
		analysisTypeToUseCase(inArgs),
		false)
	if err != nil {
		return "", err
	}

	outFormat := getOutputFormat(inArgs)
	analysisOut, err := og.Generate(outFormat, outFile)
	if err != nil {
		return "", fmt.Errorf(ErrorFormat, OutGenerationErr, err)
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

	if *inArgs.Version {
		fmt.Printf("vpc-network-config-analyzer v%s\n", version.VersionCore)
		return nil
	}

	rc, err1 := ibmvpc.ParseResourcesFromFile(*inArgs.InputConfigFile)
	if err1 != nil {
		return fmt.Errorf("error parsing input vpc resources file: %w", err1)
	}

	vpcConfigs, err2 := ibmvpc.VPCConfigsFromResources(rc, *inArgs.VPC, *inArgs.Debug)
	if err2 != nil {
		return fmt.Errorf(ErrorFormat, InGenerationErr, err2)
	}

	outFile := ""
	if inArgs.OutputFile != nil {
		outFile = *inArgs.OutputFile
	}

	diffAnalysis := *inArgs.AnalysisType == allEndpointsDiff || *inArgs.AnalysisType == allSubnetsDiff
	if !diffAnalysis {
		vpcAnalysisOutput, err2 := analysisVPCConfigs(vpcConfigs, nil, inArgs, outFile)
		if err2 != nil {
			return err2
		}
		fmt.Println(vpcAnalysisOutput)
	} else {
		return diffAnalysisMain(inArgs, vpcConfigs, outFile)
	}
	return nil
}

func diffAnalysisMain(inArgs *InArgs, vpcConfigs map[string]*vpcmodel.VPCConfig, outFile string) error {
	// ToDo SM: for diff analysis assume 2 configs only, the 2nd given through vpc-config-second
	rc2ndForDiff, err1 := ibmvpc.ParseResourcesFromFile(*inArgs.InputSecondConfigFile)
	if err1 != nil {
		return fmt.Errorf(ErrorFormat, ParsingErr, err1)
	}
	vpc2ndConfigs, err2 := ibmvpc.VPCConfigsFromResources(rc2ndForDiff, *inArgs.VPC, *inArgs.Debug)
	if err2 != nil {
		return fmt.Errorf(ErrorFormat, InGenerationErr, err2)
	}
	// For diff analysis each vpcConfigs have a single element
	if len(vpcConfigs) != 1 || len(vpc2ndConfigs) != 1 {
		return fmt.Errorf("for diff mode %v a single configuration should be provided "+
			"for both -vpc-config and -vpc-config-second", *inArgs.AnalysisType)
	}
	analysisOutput, err2 := analysisVPCConfigs(vpcConfigs, vpc2ndConfigs, inArgs, outFile)
	if err2 != nil {
		return err2
	}
	fmt.Println(analysisOutput)
	return nil
}

func main() {
	err := _main(os.Args[1:])
	if err != nil {
		log.Fatalf("%v. exiting...", err)
	}
}
