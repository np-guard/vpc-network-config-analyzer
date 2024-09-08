/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/models/pkg/netp"
)

type ExplanationArgs struct {
	src        string
	dst        string
	protocol   string
	srcMinPort int64
	srcMaxPort int64
	dstMinPort int64
	dstMaxPort int64
	detail     bool
}

func (e *ExplanationArgs) Src() string {
	return e.src
}

func (e *ExplanationArgs) Dst() string {
	return e.dst
}

// consts for managing errors from the single vpc context in the global, multi-vpc, context.
// error are prioritized: the larger the error, the higher its severity
const (
	noErr                        = iota
	noValidInputErr              // string does not represent a valid input w.r.t. this config - wait until we go over all vpcs
	internalNoConnectedEndpoints // internal address not connected to any of the VPC's eps - wait until we go over all vpcs
	fatalErr                     // fatal error that implies immediate termination (do not wait until we go over all vpcs)
)

const noValidInputMsg = "is not a legal IP address, CIDR, or endpoint name"

const Deliminator = "/"

type srcAndDstNodes struct {
	srcNodes []Node
	dstNodes []Node
}

// getVPCConfigAndSrcDstNodes given src, dst in string returns the config in which the exaplainability analysis of these
// should be done and the Nodes for src and dst. It also returns whether src and/or dst was given as the internal address of
// an endpoint - which effects the output.
// src/dst when referring to an endpoint *name* may be prefixed with the vpc name with the deliminator "/" to solve ambiguity
// If such prefix is missing then a match in any vpc is valid.
// At most one config should contain both src and dst, and this is the config returned:
// * If one is internal and the other is external the vpcConfig of the internal is returned
// * If both are internal then at most one VPC should contain both:
// ** If both internals are in the same VPC then the config of that VPC contains both and will be returned
// ** If the two internals are of different VPCs then the mutli-VPC of the tgw that connects the two VPC contains both
// this is the vpcConfig that will be returned, if such tgw exists; if such a tgw does not exist the src and dst are not connected
// At this stage, we do not support the following:
// 1. two tgw connects src and dst;
// 2. src and/or dst has endpoint(s) in more than one VPC

// error handling: the src and dst are being searched for within the context of each vpcConfig.
// if no match found, then it is due to one of the following errors:
// 1. src identical to dst
// 2. Both src and dst are external IP addresses
// 3. Src/dst is a CIDR that contains both internal and external IP addresses
// 4. Src/dst matches more than one EP. Use VPC-name prefixes or CRNs
// 5. Src/dst is an internal address not connected to any endpoint
// 6. Src/dst is not a legal endpoint name and is not a legal IP address
// errors 1-4, although detected within a specific VPC Context, are relevant in the multi-vpc
// context and as such results in an immediate return with the error message (fatal error).
// error 4 can be interpreted as a non-fatal error in the multiVPC context, but is treated as fatal since
// it is much safer, in case there are EPs with identical names cross VPC, to specify explicitly which is the relevant VPC for each EP
// error 5 is not fatal since a given cidr may overlap APs of more than one VPC but have EPs only in one VPC
// similarly, error 6 may occur in one vpcConfig while there is still a match to src and dst in another one
//
// More than one match found is also considered an error. It can be due to one of the following:
// 1. src and dst are of different VPCs and are connected by more than one tgw
// 2. src and dst are internal address containing endpoints in more than one VPC
// 3. src (dst) is internal containing endpoints in more than one VPC and dst (src) is external
// neither are supported in this stage
// todo: note that there could be cases in which src/dst are internal address that contains EPs of more than one VPC
//       which will not result in an error. E.g., src is a endpoint of VPC1 and dst is an internal address of VPC1
//       and VPC2. in this case explainability analysis will be done for VPC1

//nolint:gocyclo // better not split into two function
func (c *MultipleVPCConfigs) getVPCConfigAndSrcDstNodes(src, dst string) (vpcConfig *VPCConfig,
	srcNodes, dstNodes []Node, err error) {
	var errMsgInternalNoEP, errMsgNoValidSrc, errMsgNoValidDst error
	var srcFoundSomeCfg, dstFoundSomeCfg bool
	if unifyInput(src) == unifyInput(dst) {
		return nil, nil, nil, fmt.Errorf("specified src and dst are equal")
	}
	configsWithSrcDstNodeSingleVpc, configsWithSrcDstNodeMultiVpc := map[string]srcAndDstNodes{}, map[string]srcAndDstNodes{}
	for cfgID := range c.Configs() {
		var errType int
		srcNodes, dstNodes, errType, err = c.Config(cfgID).srcDstInputToNodes(src, dst)
		if srcNodes != nil {
			srcFoundSomeCfg = true
		}
		if dstNodes != nil {
			dstFoundSomeCfg = true
		}
		if err != nil {
			switch {
			case errType == fatalErr:
				return c.Config(cfgID), nil, nil, err
			case errType == internalNoConnectedEndpoints:
				errMsgInternalNoEP = err
			case errType == noValidInputErr && srcNodes == nil:
				errMsgNoValidSrc = err
			case errType == noValidInputErr: // srcNodes != nil, dstNodes == nil
				errMsgNoValidDst = err
			}
		} else {
			if c.Config(cfgID).IsMultipleVPCsConfig {
				configsWithSrcDstNodeMultiVpc[cfgID] = srcAndDstNodes{srcNodes, dstNodes}
			} else {
				configsWithSrcDstNodeSingleVpc[cfgID] = srcAndDstNodes{srcNodes, dstNodes}
			}
		}
	}
	switch {
	// no match: no single vpc config or multi vpc config in which a match for both src and dst was found
	// this can be either a result of input error, or of src and dst of different vpc that are not connected via cross-vpc router
	case len(configsWithSrcDstNodeSingleVpc) == 0 && len(configsWithSrcDstNodeMultiVpc) == 0:
		return noConfigMatchSrcDst(srcFoundSomeCfg, dstFoundSomeCfg, errMsgInternalNoEP,
			errMsgNoValidSrc, errMsgNoValidDst)
	// single config in which both src and dst were found, and the matched config is a multi vpc config: returns the matched config
	case len(configsWithSrcDstNodeSingleVpc) == 0 && len(configsWithSrcDstNodeMultiVpc) == 1:
		for cfgID, val := range configsWithSrcDstNodeMultiVpc {
			return c.Config(cfgID), val.srcNodes, val.dstNodes, nil
		}
	// Src and dst were found in a exactly one single-vpc config. Its likely src and dst were also found in
	// multi-vpc configs (in each such config that connects their vpc to another one).
	// In this case the relevant config for analysis is the single vpc config, which is the returned config
	case len(configsWithSrcDstNodeSingleVpc) == 1:
		for cfgID, val := range configsWithSrcDstNodeSingleVpc {
			return c.Config(cfgID), val.srcNodes, val.dstNodes, nil
		}
	// both src and dst found in *more than one* single-vpc config or
	// in no single-vpc config and more than one multi-vpc config. In both cases it is impossible to determine
	// what is the config in which the analysis should be done
	default:
		return nil, nil, nil,
			c.matchMoreThanOneSingleVpcCfgError(src, dst, configsWithSrcDstNodeSingleVpc, configsWithSrcDstNodeMultiVpc)
	}
	return nil, nil, nil, nil
}

func unifyInput(str string) string {
	return strings.TrimSuffix(str, "/32")
}

// no match for both src and dst in any of the cfgs:
// this can be either a result of input error, or of src and dst of different vpc that are not connected via cross-vpc router
// prioritizes cases and possible errors as follows:
// valid input but no cross vpc router >  errMsgInternalNoEP > errMsgNoValidSrc > errMsgNoValidDst
// this function was tested manually; having a dedicated test for it is too much work w.r.t its simplicity
func noConfigMatchSrcDst(srcFoundSomeCfg, dstFoundSomeCfg bool, errMsgInternalNoEP,
	errMsgNoValidSrc, errMsgNoValidDst error) (vpcConfig *VPCConfig,
	srcNodes, dstNodes []Node, err error) {
	switch {
	// src found some cfg, dst found some cfg but not in the same cfg: input valid (missing tgw)
	// this is not considered an error - the output will explain the src, dst are not connected via cross-vpc router
	case srcFoundSomeCfg && dstFoundSomeCfg:
		return nil, nil, nil, nil
	case errMsgInternalNoEP != nil:
		return nil, nil, nil, errMsgInternalNoEP
	case !srcFoundSomeCfg:
		return nil, nil, nil, errMsgNoValidSrc
	default: // !dstFoundSomeCfg:
		return nil, nil, nil, errMsgNoValidDst
	}
}

// src, dst found in more than one config error:
// more than one match of single config or
// non match of single config and more than one match of multiple config
func (c *MultipleVPCConfigs) matchMoreThanOneSingleVpcCfgError(src, dst string,
	configsWithSrcDstNodeSingleVpc, configsWithSrcDstNodeMultiVpc map[string]srcAndDstNodes) error {
	if len(configsWithSrcDstNodeSingleVpc) > 1 { // more than single vpc config
		matchConfigsStr := c.listNamesCfg(configsWithSrcDstNodeSingleVpc)
		return fmt.Errorf("%s and %s found in more than one vpc config - %s - "+
			"please add the name of the vpc to the src/dst name in case of name ambiguity, "+
			"and avoid cidrs that spams more than one vpc", src, dst, matchConfigsStr)
	}
	listNamesCrossVpcRouters, err := c.listNamesCrossVpcRouters(configsWithSrcDstNodeMultiVpc)
	if err != nil {
		return err
	}
	return fmt.Errorf("the src and dst are in separate VPCs connected by multiple transit gateways (%s). "+
		"This scenario is currently not supported", listNamesCrossVpcRouters)
}

func (c *MultipleVPCConfigs) listNamesCfg(configsWithSrcDstNode map[string]srcAndDstNodes) string {
	i := 0
	matchConfigs := make([]string, len(configsWithSrcDstNode))
	for vpcUID := range configsWithSrcDstNode {
		// the endpoints are in more than one config; lists all the configs it is in for the error msg
		matchConfigs[i] = c.Config(vpcUID).VPC.Name()
		i++
	}
	sort.Strings(matchConfigs)
	return strings.Join(matchConfigs, comma)
}

// returns list of tgw in vpcs of configsWithSrcDstNodeMultiVpc
// since the map is of multi-vpc configs (IsMultipleVPCsConfig true) each must have a cross-vpc router (tgw)
func (c *MultipleVPCConfigs) listNamesCrossVpcRouters(
	configsWithSrcDstNode map[string]srcAndDstNodes) (string, error) {
	i := 0
	crossVpcRouters := make([]string, len(configsWithSrcDstNode))
	for vpcUID := range configsWithSrcDstNode {
		routingResources := c.Config(vpcUID).RoutingResources
		if len(routingResources) != 1 {
			return "", fmt.Errorf("np-guard error: multi-vpc config %s should have a single routing resource, "+
				"but has %v routing resources", c.Config(vpcUID).VPC.Name(), len(routingResources))
		}
		crossVpcRouters[i] = routingResources[0].Name()
		i++
	}
	sort.Strings(crossVpcRouters)
	return strings.Join(crossVpcRouters, comma), nil
}

// GetConnectionSet TODO: handle also input ICMP properties (type, code) as input args
// translates explanation args to a connection set
func (e *ExplanationArgs) GetConnectionSet() *connection.Set {
	if e.protocol == "" {
		return nil
	}
	switch p := netp.ProtocolString(e.protocol); p {
	case netp.ProtocolStringICMP:
		return connection.ICMPConnection(
			connection.MinICMPType, connection.MaxICMPType,
			connection.MinICMPCode, connection.MaxICMPCode)
	default:
		return connection.TCPorUDPConnection(p,
			e.srcMinPort, e.srcMaxPort, e.dstMinPort, e.dstMaxPort)
	}
}

// given src and dst input and a VPCConfigs finds the []nodes they represent in the config
// src/dst may refer to:
// 1. Endpoint by UID or name; in this case we consider the network interfaces of the endpoint
// 2. Subnet by name; in this case we consider its internal address, see next item
// 3. Internal IP address or cidr; in this case we consider the endpoints in that address range
// 4. external IP address or cidr
func (c *VPCConfig) srcDstInputToNodes(srcName, dstName string) (srcNodes,
	dstNodes []Node, errType int, err error) {
	var errSrc, errDst error
	var errSrcType, errDstType int
	srcNodes, errSrcType, errSrc = c.getSrcOrDstInputNode(srcName, "src")
	dstNodes, errDstType, errDst = c.getSrcOrDstInputNode(dstName, "dst")
	switch {
	case errSrcType > errDstType: // src's error is of severity larger than dst's error;
		// this implies src has an error (dst may have an error and may not have an error)
		return srcNodes, dstNodes, errSrcType, errSrc
	case errDstType > errSrcType: // same as above src <-> dst
		return srcNodes, dstNodes, errDstType, errDst
	default: // both of the same severity, could be no error
		if errSrc != nil { // if an error, prioritize src
			return srcNodes, dstNodes, errSrcType, errSrc
		}
	}
	// both src and dst are legal
	// only one of src/dst may be external; there could be multiple nodes only if external
	if !srcNodes[0].IsInternal() && !dstNodes[0].IsInternal() {
		return srcNodes, dstNodes, fatalErr,
			fmt.Errorf("both src %v and dst %v are external IP addresses", srcName, dstName)
	}
	return srcNodes, dstNodes, noErr, nil
}

// given a VPCConfig and a string looks for the endpoint/Internal IP/External address it presents,
// as described above
func (c *VPCConfig) getSrcOrDstInputNode(name, srcOrDst string) (nodes []Node,
	errType int, err error) {
	outNodes, errType1, err1 := c.getNodesFromInputString(name)
	if err1 != nil {
		return nil, errType1, fmt.Errorf("illegal %v: %v", srcOrDst, err1.Error())
	}
	return outNodes, noErr, nil
}

// given a VPCConfig and a string cidrOrName representing a subnet, an endpoint or internal/external
// cidr/address returns the corresponding node(s) and a bool which is true iff
// cidrOrName is an internal address and the nodes are its network interfaces
func (c *VPCConfig) getNodesFromInputString(cidrOrName string) (nodes []Node,
	errType int, err error) {
	// 1. cidrOrName references endpoint
	endpoint, errType1, err1 := c.getNodesOfEndpoint(cidrOrName)
	if err1 != nil {
		return nil, errType1, err1
	}
	if endpoint != nil {
		return endpoint, noErr, nil
	}
	// cidrOrName, if legal, references an address.
	// 2. cidrOrName references an ip address
	ipBlock, err2 := ipblock.FromCidrOrAddress(cidrOrName)
	if err2 != nil {
		// the input is not a legal cidr or IP address, which in this stage means it is not a
		// valid presentation for src/dst. Lint demands that an error is returned here
		return nil, noValidInputErr,
			fmt.Errorf("%s %s", cidrOrName, noValidInputMsg)
	}
	// the input is a legal cidr or IP address
	return c.getNodesFromAddress(cidrOrName, ipBlock)
}

// getNodesOfEndpoint gets a string name or UID of an endpoint (e.g. VSI), and
// returns the list of all nodes within this endpoint
func (c *VPCConfig) getNodesOfEndpoint(name string) ([]Node, int, error) {
	var nodeSetOfEndpoint NodeSet
	// endpoint name may be prefixed by vpc name
	var vpc, endpoint string
	uid := name // uid specified - vpc prefix is not relevant and uid may contain the deliminator "/"
	cidrOrNameSlice := strings.Split(name, Deliminator)
	switch len(cidrOrNameSlice) {
	case 1: // vpc name not specified
		endpoint = name
	case 2: // vpc name specified
		vpc = cidrOrNameSlice[0]
		endpoint = cidrOrNameSlice[1]
	}
	for _, nodeSet := range append(c.NodeSets, c.loadBalancersAsNodeSets()...) {
		if (vpc == "" || nodeSet.VPC().Name() == vpc) && nodeSet.Name() == endpoint || // if vpc of endpoint specified, equality must hold
			nodeSet.UID() == uid {
			if nodeSetOfEndpoint != nil {
				return nil, fatalErr, fmt.Errorf("ambiguity - the configuration contains multiple resources named %s, "+
					"try using CRNs or the VPC name to scope resources: vpc-name/instance-name"+
					"\nCRNs of matching resources:\n\t%s\n\t%s", name, nodeSetOfEndpoint.UID(), nodeSet.UID())
			}
			nodeSetOfEndpoint = nodeSet
		}
	}
	if nodeSetOfEndpoint == nil {
		return nil, noErr, nil
	}
	return nodeSetOfEndpoint.Nodes(), noErr, nil
}

// getNodesFromAddress gets a string and IPBlock that represents a cidr or IP address
// and returns the corresponding node(s)and a bool which is true iff ipOrCidr is an internal address.
// Specifically:
//  1. If it represents a cidr which is both internal and external, returns an error
//  2. If it presents an external address, returns external addresses nodes and false
//  3. No endpoints connected to the internal address, returns an error
//  4. else: it presents an internal address, return connected network interfaces and true,
//
// todo: 4 - replace subnet's address range in vpc's address prefix
func (c *VPCConfig) getNodesFromAddress(ipOrCidr string, inputIPBlock *ipblock.IPBlock) (nodes []Node,
	errType int, err error) {
	// 1.
	_, publicInternet, err1 := GetPublicInternetIPblocksList()
	if err1 != nil { // should never get here. If still gets here - severe error, quit with err msg
		return nil, fatalErr, err1
	}
	isExternal := inputIPBlock.Overlap(publicInternet)
	isInternal := !inputIPBlock.ContainedIn(publicInternet)
	if isInternal && isExternal {
		return nil, fatalErr,
			fmt.Errorf("%s contains both external and internal IP addresses, which is not supported. "+
				"src, dst should be external *or* internal address", ipOrCidr)
	}
	// 2.
	if isExternal {
		nodes, errType, err = c.getCidrExternalNodes(inputIPBlock)
		if err != nil { // should never get here.
			return nil, errType, err
		}
		return nodes, noErr, nil
	}
	// internal address
	networkInterfaces := c.GetNodesWithinInternalAddress(inputIPBlock)
	if len(networkInterfaces) == 0 { // 3.
		return nil, internalNoConnectedEndpoints, fmt.Errorf("no network interfaces are connected to %s", ipOrCidr)
	}
	return networkInterfaces, noErr, nil // 4.
}

// given input IPBlock, gets (disjoint) external nodes I s.t.:
//  1. The union of these nodes is the cidr
//  2. Let i be a node in I and n be a node in VPCConfig.
//     i and n are either disjoint or i is contained in n
//     Note that the vpconfig nodes were chosen w.r.t. connectivity rules (SG and NACL)
//     s.t. each node either fully belongs to a rule or is disjoint to it.
//     to get nodes I as above:
//  1. Calculate the IP blocks of the nodes N
//  2. Calculate from N and the cidr block, disjoint IP blocks
//  3. Return the nodes created from each block from 2 contained in the input cidr
func (c *VPCConfig) getCidrExternalNodes(inputIPBlock *ipblock.IPBlock) (cidrNodes []Node, errType int, err error) {
	// 1.
	vpcConfigNodesExternalBlock := []*ipblock.IPBlock{}
	for _, node := range c.Nodes {
		if node.IsInternal() {
			continue
		}
		vpcConfigNodesExternalBlock = append(vpcConfigNodesExternalBlock, node.IPBlock())
	}
	// 2.
	disjointBlocks := ipblock.DisjointIPBlocks([]*ipblock.IPBlock{inputIPBlock}, vpcConfigNodesExternalBlock)
	// 3.
	cidrNodes = []Node{}
	for _, block := range disjointBlocks {
		if block.ContainedIn(inputIPBlock) {
			node, err1 := newExternalNode(true, block)
			if err1 != nil {
				return nil, fatalErr, err1 // Should never get here. If still does - severe bug, exit with err
			}
			cidrNodes = append(cidrNodes, node)
		}
	}
	return cidrNodes, noErr, nil
}
