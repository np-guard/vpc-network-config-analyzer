package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/np-guard/cloud-resource-collector/pkg/factory"
	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
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
	case explainMode:
		return vpcmodel.Explain
	}
	return vpcmodel.AllEndpoints
}

func analysisVPCConfigs(c1, c2 map[string]*vpcmodel.VPCConfig, inArgs *InArgs, outFile string) (string, error) {
	var explanationArgs *vpcmodel.ExplanationArgs
	if *inArgs.AnalysisType == explainMode {
		explanationArgs = vpcmodel.NewExplanationArgs(*inArgs.ESrc, *inArgs.EDst, *inArgs.EProtocol,
			*inArgs.ESrcMinPort, *inArgs.ESrcMaxPort, *inArgs.EDstMinPort, *inArgs.EDstMaxPort)
	}

	og, err := vpcmodel.NewOutputGenerator(c1, c2,
		*inArgs.Grouping,
		analysisTypeToUseCase(inArgs),
		false,
		explanationArgs)
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

func vpcConfigsFromFile(fileName string, inArgs *InArgs) (map[string]*vpcmodel.VPCConfig, error) {
	rc, err1 := ibmvpc.ParseResourcesFromFile(fileName)
	if err1 != nil {
		return nil, fmt.Errorf("error parsing input vpc resources file: %w", err1)
	}

	vpcConfigs, err2 := ibmvpc.VPCConfigsFromResources(rc, *inArgs.VPC, *inArgs.Debug)
	if err2 != nil {
		return nil, fmt.Errorf(ErrorFormat, InGenerationErr, err2)
	}
	return vpcConfigs, nil
}

func vpcConfigsFromAccount(inArgs *InArgs) (map[string]*vpcmodel.VPCConfig, error) {
	rc := factory.GetResourceContainer(*inArgs.Provider, inArgs.RegionList, *inArgs.ResourceGroup)
	// Collect resources from the provider API and generate output
	err := rc.CollectResourcesFromAPI()
	if err != nil {
		return nil, err
	}

	// todo: when analysis for other providers is available, select provider according to flag
	resources, ok := rc.GetResources().(*datamodel.ResourcesContainerModel)
	if !ok {
		return nil, fmt.Errorf("error casting resources to *datamodel.ResourcesContainerModel type")
	}
	vpcConfigs, err := ibmvpc.VPCConfigsFromResources(resources, *inArgs.VPC, *inArgs.Debug)
	if err != nil {
		return nil, err
	}
	return vpcConfigs, nil
}

// The actual main function
// Takes command-line flags and returns an error rather than exiting, so it can be more easily used in testing
func _main(cmdlineArgs []string) error {
	inArgs, err := ParseInArgs(cmdlineArgs)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return fmt.Errorf(ErrorFormat, ParsingErr, err)
	}

	if *inArgs.Version {
		fmt.Printf("vpc-network-config-analyzer v%s\n", version.VersionCore)
		return nil
	}

	var vpcConfigs1 map[string]*vpcmodel.VPCConfig
	if *inArgs.Provider != "" {
		vpcConfigs1, err = vpcConfigsFromAccount(inArgs)
		if err != nil {
			return err
		}
	} else {
		vpcConfigs1, err = vpcConfigsFromFile(*inArgs.InputConfigFile, inArgs)
		if err != nil {
			return err
		}
	}

	var vpcConfigs2 map[string]*vpcmodel.VPCConfig
	if inArgs.InputSecondConfigFile != nil && *inArgs.InputSecondConfigFile != "" {
		vpcConfigs2, err = vpcConfigsFromFile(*inArgs.InputSecondConfigFile, inArgs)
		if err != nil {
			return err
		}
		// we are in diff mode, checking we have only one config per file:
		if len(vpcConfigs1) != 1 || len(vpcConfigs2) != 1 {
			return fmt.Errorf("for diff mode %v a single configuration should be provided "+
				"for both -vpc-config and -vpc-config-second", *inArgs.AnalysisType)
		}
	}
	outFile := ""
	if inArgs.OutputFile != nil {
		outFile = *inArgs.OutputFile
	}
	vpcAnalysisOutput, err2 := analysisVPCConfigs(vpcConfigs1, vpcConfigs2, inArgs, outFile)
	if err2 != nil {
		return err2
	}
	fmt.Println(vpcAnalysisOutput)

	return nil
}

func main() {
	err := _main(os.Args[1:])
	if err != nil {
		log.Fatalf("%v. exiting...", err)
	}
}
