/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subcmds

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/np-guard/cloud-resource-collector/pkg/common"
	"github.com/np-guard/cloud-resource-collector/pkg/factory"
	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/awsvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/ibmvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const notSupportedYet = "provider %s is not supported yet"

// Helper function for unmarshalling
func jsonToMap(jsonStr []byte) (map[string]json.RawMessage, error) {
	var result map[string]json.RawMessage
	err := json.Unmarshal(jsonStr, &result)
	return result, err
}

// parseProviderFromFile returns the provider (ibm or aws) from the input JSON file
func parseProviderFromFile(fileName string) (common.Provider, error) {
	inputConfigContent, err := os.ReadFile(fileName)
	if err != nil {
		return "", err
	}
	asMap, err := jsonToMap(inputConfigContent)
	if err != nil {
		return "", err
	}
	provider := common.IBM
	val, ok := asMap["provider"]
	if ok {
		if err := json.Unmarshal(val, &provider); err != nil {
			return "", err
		}
	}
	return provider, nil
}

func vpcConfigsFromFiles(fileNames []string, inArgs *inArgs) (*vpcmodel.MultipleVPCConfigs, error) {
	// len(fileNames) can not be zero
	provider, err := parseProviderFromFile(fileNames[0])
	if err != nil {
		return nil, err
	}
	switch provider {
	case common.IBM:
		rc := ibmvpc.IBMresourcesContainer{}
		return rc.VpcConfigsFromFiles(fileNames, inArgs.vpc, inArgs.resourceGroup, inArgs.regionList)
	case common.AWS:
		rc := awsvpc.AWSresourcesContainer{}
		return rc.VpcConfigsFromFiles(fileNames, inArgs.vpc, inArgs.resourceGroup, inArgs.regionList)
	default:
		return nil, fmt.Errorf(notSupportedYet, provider)
	}
}

func vpcConfigsFromAccount(inArgs *inArgs) (*vpcmodel.MultipleVPCConfigs, error) {
	rc := factory.GetResourceContainer(inArgs.provider, inArgs.regionList, inArgs.resourceGroup)
	// Collect resources from the provider API and generate output
	err := rc.CollectResourcesFromAPI()
	if err != nil {
		return nil, err
	}

	var vpcConfigs *vpcmodel.MultipleVPCConfigs
	// todo: when analysis for other providers is available, select provider according to flag
	if inArgs.provider == common.IBM {
		ibmResources, ok := rc.GetResources().(*datamodel.ResourcesContainerModel)
		if !ok {
			return nil, fmt.Errorf("error casting resources to *datamodel.ResourcesContainerModel type")
		}
		rc := ibmvpc.IBMresourcesContainer{ResourcesContainerModel: *ibmResources}
		vpcConfigs, err = rc.VPCConfigsFromResources(inArgs.vpc, inArgs.resourceGroup, inArgs.regionList)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf(notSupportedYet, inArgs.provider.String())
	}

	// save collected resources in dump file
	if inArgs.dumpResources != "" {
		jsonString, err := rc.ToJSONString()
		if err != nil {
			return nil, err
		}
		log.Printf("Dumping collected resources to file: %s", inArgs.dumpResources)

		file, err := os.Create(inArgs.dumpResources)
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

func buildConfigs(inArgs *inArgs) (vpcConfigs *vpcmodel.MultipleVPCConfigs, err error) {
	if inArgs.provider != "" {
		vpcConfigs, err = vpcConfigsFromAccount(inArgs)
		if err != nil {
			return
		}
	} else {
		vpcConfigs, err = vpcConfigsFromFiles(inArgs.inputConfigFileList, inArgs)
		if err != nil {
			return
		}
	}

	if inArgs.inputSecondConfigFile != "" {
		vpcConfigsToCompare, err := vpcConfigsFromFiles([]string{inArgs.inputSecondConfigFile}, inArgs)
		if err != nil {
			return nil, err
		}
		// we are in diff mode, checking we have only one config per file:
		if len(vpcConfigs.Configs()) != 1 || len(vpcConfigsToCompare.Configs()) != 1 {
			return nil, fmt.Errorf("diff command only supports a single configuration " +
				"for both --config and --config-second")
		}
		vpcConfigs.SetConfigsToCompare(vpcConfigsToCompare.Configs())
	}

	return vpcConfigs, nil
}
