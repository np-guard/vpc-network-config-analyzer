/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"sort"
	"strconv"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/spec"
)

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
		all = GetSpec(conn.GroupedConnectivity.GroupedLines)
	case AllSubnets:
		all = GetSpec(subnetsConn.GroupedConnectivity.GroupedLines)
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

func handleNameAndType(resource EndpointElem, externalsMap map[string]string, externals spec.SpecExternals) (
	resourceName string,
	resourceType spec.ResourceType) {
	resourceName, nifNumber := resource.DetailedResourceForSynthesisOut() // for synthesis output return two
	if resource.IsExternal() {
		if structObj, ok := resource.(*groupedExternalNodes); ok {
			// should be always true if src is external
			resourceName = handleExternals(resourceName, structObj.CidrOrAddress(), externalsMap, externals)
		}
	}
	resourceType = resource.SynthesisKind()

	// if this nif's vsi has only one nif, we convert it to instance type with name of the instance
	// because the name of the nif will be meaningless for the user if there is one generated nif.
	if resourceType == spec.ResourceTypeNif && nifNumber == 1 {
		resourceType = spec.ResourceTypeInstance
	}
	return
}

func GetSpec(groupedLines []*groupedConnLine) spec.Spec {
	s := spec.Spec{}
	connLines := []spec.SpecRequiredConnectionsElem{}
	externals := spec.SpecExternals{}
	externalsMap := make(map[string]string)
	sortGroupedLines(groupedLines)

	for _, groupedLine := range groupedLines {
		srcName, srcType := handleNameAndType(groupedLine.Src, externalsMap, externals)
		dstName, dstType := handleNameAndType(groupedLine.Dst, externalsMap, externals)
		if groupedLine.CommonProperties.Conn.isEmpty() {
			continue
		}
		connLines = append(connLines, spec.SpecRequiredConnectionsElem{
			Src:              spec.Resource{Name: srcName, Type: srcType},
			Dst:              spec.Resource{Name: dstName, Type: dstType},
			AllowedProtocols: sortProtocolList(spec.ProtocolList(connection.ToJSON(groupedLine.CommonProperties.Conn.allConn)))})
	}
	s.Externals = externals
	s.RequiredConnections = connLines
	return s
}

func sortProtocolList(g spec.ProtocolList) spec.ProtocolList {
	sort.Slice(g, func(i, j int) bool {
		if _, ok := g[i].(spec.AnyProtocol); ok {
			// the other struct can not have the same protocol
			return true
		}
		if _, ok := g[j].(spec.AnyProtocol); ok {
			// the other struct can not have the same protocol
			return false
		}
		if s1, ok := g[i].(spec.TcpUdp); ok {
			// the other struct can be tcp, udp or icmp
			if s2, ok := g[j].(spec.TcpUdp); ok {
				switch {
				case s1.Protocol != s2.Protocol:
					return s1.Protocol > s2.Protocol

				case s1.MinSourcePort != s2.MinSourcePort:
					return s1.MinSourcePort > s2.MinSourcePort
				case s1.MinDestinationPort != s2.MinDestinationPort:
					return s1.MinDestinationPort > s2.MinDestinationPort
				case s1.MaxSourcePort != s2.MaxSourcePort:
					return s1.MaxSourcePort > s2.MaxSourcePort
				default:
					return s1.MaxDestinationPort > s2.MaxDestinationPort
				}
			}
			// the other struct is icmp
			return true
		}

		if _, ok := g[j].(spec.TcpUdp); ok {
			// the other struct can be just icmp
			return false
		}

		// both are icmp
		s1, _ := g[i].(spec.Icmp)
		// must be ok
		s2, _ := g[j].(spec.Icmp)
		if *s1.Code != *s2.Code {
			return *s1.Code > *s2.Code
		}
		return *s1.Type > *s2.Type
	})
	return g
}

func sortGroupedLines(g []*groupedConnLine) {
	sort.Slice(g, func(i, j int) bool {
		if g[i].Src.Name() != g[j].Src.Name() {
			return g[i].Src.Name() > g[j].Src.Name()
		} else if g[i].Dst.Name() != g[j].Dst.Name() {
			return g[i].Dst.Name() > g[j].Dst.Name()
		}
		return g[i].CommonProperties.Conn.string() > g[j].CommonProperties.Conn.string()
	})
}
