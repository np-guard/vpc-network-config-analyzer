/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/spec"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/logging"
)

const skippingResource = "skipping resource %s, err: %v\n"

type SynthesisOutputFormatter struct {
}

func (j *SynthesisOutputFormatter) WriteOutput(c1, c2 *VPCConfig,
	conn *VPCConnectivity,
	subnetsConn *VPCsubnetConnectivity,
	cfgsDiff *diffBetweenCfgs,
	outFile string,
	grouping bool,
	uc OutputUseCase,
	explanation *Explanation, detailExplain bool) (*SingleAnalysisOutput, error) {
	var all interface{}
	switch uc {
	case AllEndpoints:
		all = getSpec(conn.AllowedConnsCombinedResponsive)
	case AllSubnets:
		all = getSpec(subnetsConn.AllowedConnsCombinedResponsive)
	}
	outStr, err := writeJSON(all, outFile)
	v2Name := ""
	if c2 != nil {
		v2Name = c2.VPC.Name()
	}
	return &SingleAnalysisOutput{Output: outStr, VPC1Name: c1.VPC.Name(), VPC2Name: v2Name, format: Synthesis, jsonStruct: all}, err
}

func handleExternals(srcName, cidrOrAddress string, externalsMap map[string]string, externals spec.SpecExternals) string {
	if val, ok := externalsMap[srcName]; ok {
		return val
	}
	name := "external" + strconv.Itoa(len(externals))
	externalsMap[srcName] = name
	externals[name] = cidrOrAddress
	return name
}

func handleTypes(kind string) (spec.ResourceType, error) {
	switch kind { // resourceTypes that can appear in connectivityMap.
	case ResourceTypeSubnet:
		return spec.ResourceTypeSubnet, nil
	case ResourceTypeVSI:
		return spec.ResourceTypeInstance, nil
	case ResourceTypeNetworkInterface:
		return spec.ResourceTypeNif, nil
	default:
		return "", fmt.Errorf("resourceType %s is not supported yet", kind)
	}
}

func handleNameAndType(resource VPCResourceIntf, externalsMap map[string]string, externals spec.SpecExternals) (
	resourceName string,
	resourceType spec.ResourceType,
	err error) {
	resourceName = resource.ResourceNameFromConfig()
	if resource.IsExternal() {
		resourceType = spec.ResourceTypeExternal
		if structObj, ok := resource.(*ExternalNetwork); ok {
			// should be always true if src is external
			resourceName = handleExternals(resourceName, structObj.CidrOrAddress(), externalsMap, externals)
		}
	} else {
		resourceType, err = handleTypes(resource.Kind())
		if err != nil {
			logging.Warnf(skippingResource, resourceName, err)
			return
		}
	}
	// todo; handle nif, replace it with instance type if there is just one nif for it's vsi
	return
}

func getSpec(allowedConnsCombinedResponsive GeneralResponsiveConnectivityMap) spec.Spec {
	s := spec.Spec{}
	connLines := []spec.SpecRequiredConnectionsElem{}
	externals := spec.SpecExternals{}
	externalsMap := make(map[string]string)

	for src, srcMap := range allowedConnsCombinedResponsive {
		srcName, srcType, err := handleNameAndType(src, externalsMap, externals)
		if err != nil {
			continue
		}
		for dst, extConn := range srcMap {
			if extConn.isEmpty() {
				continue
			}
			dstName, dstType, err := handleNameAndType(dst, externalsMap, externals)
			if err != nil {
				continue
			}
			responsiveAndOther := extConn.tcpRspEnable.Union(extConn.nonTCP)
			if !extConn.TCPRspDisable.IsEmpty() {
				connLines = append(connLines, spec.SpecRequiredConnectionsElem{
					Src:              spec.Resource{Name: srcName, Type: srcType},
					Dst:              spec.Resource{Name: dstName, Type: dstType},
					AllowedProtocols: spec.ProtocolList(connection.ToJSON(responsiveAndOther))},
					spec.SpecRequiredConnectionsElem{
						Src:              spec.Resource{Name: srcName, Type: srcType},
						Dst:              spec.Resource{Name: dstName, Type: dstType},
						AllowedProtocols: spec.ProtocolList(connection.ToJSON(extConn.TCPRspDisable))},
					spec.SpecRequiredConnectionsElem{
						Src:              spec.Resource{Name: dstName, Type: dstType},
						Dst:              spec.Resource{Name: srcName, Type: srcType},
						AllowedProtocols: spec.ProtocolList(connection.ToJSON(extConn.TCPRspDisable))})
			} else {
				connLines = append(connLines, spec.SpecRequiredConnectionsElem{
					Src:              spec.Resource{Name: srcName, Type: srcType},
					Dst:              spec.Resource{Name: dstName, Type: dstType},
					AllowedProtocols: spec.ProtocolList(connection.ToJSON(extConn.allConn))})
			}
		}
	}
	sortRequiredConnections(connLines)
	s.Externals = externals
	s.RequiredConnections = connLines
	return s
}

func sortRequiredConnections(connLines []spec.SpecRequiredConnectionsElem) {
	sort.Slice(connLines, func(i, j int) bool {
		if connLines[i].Src.Name != connLines[j].Src.Name {
			return connLines[i].Src.Name < connLines[j].Src.Name
		} else if connLines[i].Dst.Name != connLines[j].Dst.Name {
			return connLines[i].Dst.Name < connLines[j].Dst.Name
		}
		return len(connLines[i].AllowedProtocols) < len(connLines[j].AllowedProtocols)
	})
}
