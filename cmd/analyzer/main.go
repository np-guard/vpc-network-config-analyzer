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
	"github.com/np-guard/vpc-network-config-analyzer/pkg/logging"
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
	case SVGFormat:
		return vpcmodel.SVG
	case ARCHSVGFormat:
		return vpcmodel.ARCHSVG
	case HTMLFormat:
		return vpcmodel.HTML
	case ARCHHTMLFormat:
		return vpcmodel.ARCHHTML
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

func analysisVPCConfigs(c1, c2 vpcmodel.MultipleVPCConfigs, inArgs *InArgs, outFile string) (string, error) {
	var explanationArgs *vpcmodel.ExplanationArgs
	if *inArgs.AnalysisType == explainMode {
		explanationArgs = vpcmodel.NewExplanationArgs(*inArgs.ESrc, *inArgs.EDst, *inArgs.EProtocol,
			*inArgs.ESrcMinPort, *inArgs.ESrcMaxPort, *inArgs.EDstMinPort, *inArgs.EDstMaxPort)
	}

	outFormat := getOutputFormat(inArgs)
	og, err := vpcmodel.NewOutputGenerator(c1, c2,
		*inArgs.Grouping,
		analysisTypeToUseCase(inArgs),
		false,
		explanationArgs, outFormat)
	if err != nil {
		return "", err
	}

	analysisOut, err := og.Generate(outFormat, outFile)
	if err != nil {
		return "", fmt.Errorf(ErrorFormat, OutGenerationErr, err)
	}

	return analysisOut, nil
}

func mergeResourcesContainers(rc1, rc2 *datamodel.ResourcesContainerModel) (*datamodel.ResourcesContainerModel, error) {
	if rc2 == nil && rc1 != nil {
		return rc1, nil
	}
	if rc2 != nil && rc1 == nil {
		return rc2, nil
	}
	if rc2 == nil && rc1 == nil {
		return nil, fmt.Errorf("error merging input vpc resources files")
	}
	rc1.VpcList = append(rc1.VpcList, rc2.VpcList...)
	rc1.SubnetList = append(rc1.SubnetList, rc2.SubnetList...)
	rc1.PublicGWList = append(rc1.PublicGWList, rc2.PublicGWList...)
	rc1.FloatingIPList = append(rc1.FloatingIPList, rc2.FloatingIPList...)
	rc1.NetworkACLList = append(rc1.NetworkACLList, rc2.NetworkACLList...)
	rc1.SecurityGroupList = append(rc1.SecurityGroupList, rc2.SecurityGroupList...)
	rc1.EndpointGWList = append(rc1.EndpointGWList, rc2.EndpointGWList...)
	rc1.InstanceList = append(rc1.InstanceList, rc2.InstanceList...)
	rc1.RoutingTableList = append(rc1.RoutingTableList, rc2.RoutingTableList...)
	rc1.LBList = append(rc1.LBList, rc2.LBList...)
	rc1.TransitConnectionList = append(rc1.TransitConnectionList, rc2.TransitConnectionList...)
	rc1.TransitGatewayList = append(rc1.TransitGatewayList, rc2.TransitGatewayList...)
	rc1.IKSClusters = append(rc1.IKSClusters, rc2.IKSClusters...)

	return rc1, nil
}

func vpcConfigsFromFiles(fileNames []string, inArgs *InArgs) (vpcmodel.MultipleVPCConfigs, error) {
	var mergedRC *datamodel.ResourcesContainerModel
	for _, file := range fileNames {
		rc, err1 := ibmvpc.ParseResourcesFromFile(file)
		if err1 != nil {
			return nil, fmt.Errorf("error parsing input vpc resources file: %w", err1)
		}
		mergedRC, err1 = mergeResourcesContainers(mergedRC, rc)
		if err1 != nil {
			return nil, err1
		}
	}
	vpcConfigs, err2 := ibmvpc.VPCConfigsFromResources(mergedRC, *inArgs.VPC, *inArgs.ResourceGroup, inArgs.RegionList, *inArgs.Debug)
	if err2 != nil {
		return nil, fmt.Errorf(ErrorFormat, InGenerationErr, err2)
	}
	return vpcConfigs, nil
}

func vpcConfigsFromAccount(inArgs *InArgs) (vpcmodel.MultipleVPCConfigs, error) {
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
	vpcConfigs, err := ibmvpc.VPCConfigsFromResources(resources, *inArgs.VPC, *inArgs.ResourceGroup, inArgs.RegionList, *inArgs.Debug)
	if err != nil {
		return nil, err
	}
	// save collected resources in dump file
	if *inArgs.DumpResources != "" {
		jsonString, err := resources.ToJSONString()
		if err != nil {
			return nil, err
		}
		log.Printf("Dumping collected resources to file: %s", *inArgs.DumpResources)

		file, err := os.Create(*inArgs.DumpResources)
		if err != nil {
			return nil, err
		}

		_, err = file.WriteString(jsonString)
		if err != nil {
			return nil, err
		}
	}
	return vpcConfigs, nil
}

// returns verbosity level based on the -q and -v switches
func getVerbosity(args *InArgs) logging.Verbosity {
	verbosity := logging.MediumVerbosity
	if *args.Quiet {
		verbosity = logging.LowVerbosity
	} else if *args.Verbose {
		verbosity = logging.HighVerbosity
	}
	return verbosity
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

	// initializes a thread-safe singleton logger
	logging.Init(getVerbosity(inArgs))

	if *inArgs.Version {
		fmt.Printf("vpc-network-config-analyzer v%s\n", version.VersionCore)
		return nil
	}

	var vpcConfigs1 vpcmodel.MultipleVPCConfigs
	if *inArgs.Provider != "" {
		vpcConfigs1, err = vpcConfigsFromAccount(inArgs)
		if err != nil {
			return err
		}
	} else {
		vpcConfigs1, err = vpcConfigsFromFiles(inArgs.InputConfigFileList, inArgs)
		if err != nil {
			return err
		}
	}

	var vpcConfigs2 vpcmodel.MultipleVPCConfigs
	if inArgs.InputSecondConfigFile != nil && *inArgs.InputSecondConfigFile != "" {
		vpcConfigs2, err = vpcConfigsFromFiles([]string{*inArgs.InputSecondConfigFile}, inArgs)
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
