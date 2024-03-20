package vpcmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/models/pkg/ipblock"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

type ExplanationArgs struct {
	src        string
	dst        string
	protocol   string
	srcMinPort int64
	srcMaxPort int64
	dstMinPort int64
	dstMaxPort int64
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
	internalNoConnectedVSI       // internal address is within vpc config's subnet addr but not connected to vsi
	internalNotWithinSubnetsAddr // internal address with not within vpc config's subnet addr - wait until we go over all vpcs
	fatalErr                     // fatal error that implies immediate termination (do not wait until we go over all vpcs)
)

const noValidInputMsg = "does not represent a legal IP address, a legal CIDR or a VSI name"

// was src/dst input provided as internal address of a vsi? this is required info since
// if this is the case then in the output the relevant detected vsis are printed
type srcDstInternalAddr struct {
	src bool
	dst bool
}

type srcAndDstNodes struct {
	srcNodes           []Node
	dstNodes           []Node
	isSrcDstInternalIP srcDstInternalAddr
}

// getVPCConfigAndSrcDstNodes given src, dst names returns the config in which the exaplainability analysis of these
// should be done and the Nodes for src and dst as well as whether src or dst was given as the internal address of
// a vsi (which effects the output)
// At most one config should contain src and dst, and this is the config returned:
// If one is internal and the other is external the vpcConfig of the internal is returned
// ToDo If both internal but of different VPCs then the relevant vpcConfig is the dummy one created for the tgw connecting them,
// if such tgw exists; otherwise the src and dst are not connected
// error handling: the src and dst are being searched for within the context of each vpcConfig.
// if not found, then it is due to one of the following:
// 1. Src/dst is an internal address not within subnets of the VPC
// 2. Src/dst is an internal address within subnets of the VPC but not connected to a vsi
// 3. Both src and dst are external address
// 4. Src/dst is a Cidr that contains both internal and external address
// 5. Src/dst does not present a legal IP address, a legal CIDR or a vsi name (vsi of the vpc)
// errors 3 and 4, although detected within a specific VPCContext, are relevant in the multi-vpc
// context and as such results in an immediate return with the error message.
// errors 1, 2 and 5 may occur in one vpcConfig while there is still a match to src and dst in another one
// if no match found error 2 > error 1 > error 5
func (configsMap MultipleVPCConfigs) getVPCConfigAndSrcDstNodes(src, dst string) (vpcConfig *VPCConfig,
	srcNodes, dstNodes []Node, isSrcDstInternalIP srcDstInternalAddr, err error) {
	var errMsgInternalNotWithinSubnet, errMsgInternalNoConnectedVSI, errMsgNoValidSrc, errMsgNoValidDst error
	var srcFoundSomeCfg, dstFoundSomeCfg bool
	noInternalIP := srcDstInternalAddr{false, false}
	configsWithSrcDstNode := map[string]srcAndDstNodes{}
	for cfgID := range configsMap {
		if configsMap[cfgID].IsMultipleVPCsConfig {
			continue // todo: tmp until we add support in tgw
		}
		var errType int
		srcNodes, dstNodes, isSrcDstInternalIP, errType, err = configsMap[cfgID].srcDstInputToNodes(src, dst, len(configsMap) > 1)
		if srcNodes != nil {
			srcFoundSomeCfg = true
		}
		if dstNodes != nil {
			dstFoundSomeCfg = true
		}
		if err != nil {
			switch {
			case errType == fatalErr:
				return configsMap[cfgID], nil, nil, noInternalIP, err
			case errType == internalNotWithinSubnetsAddr:
				errMsgInternalNotWithinSubnet = err
			case errType == internalNoConnectedVSI:
				errMsgInternalNoConnectedVSI = err
			case errType == noValidInputErr && srcNodes == nil:
				errMsgNoValidSrc = err
			case errType == noValidInputErr: // srcNodes != nil, dstNodes == nil
				errMsgNoValidDst = err
			}
		} else {
			configsWithSrcDstNode[cfgID] = srcAndDstNodes{srcNodes, dstNodes, isSrcDstInternalIP}
		}
	}
	switch len(configsWithSrcDstNode) {
	case 1: // single match: return it
		for cfgID, val := range configsWithSrcDstNode {
			return configsMap[cfgID], val.srcNodes, val.dstNodes, val.isSrcDstInternalIP, nil
		}
	case 0:
		return noMatchErr(srcFoundSomeCfg, dstFoundSomeCfg, errMsgInternalNoConnectedVSI, errMsgInternalNotWithinSubnet,
			errMsgNoValidSrc, errMsgNoValidDst)
	default: // len(configsWithSrcDstNode) > 1: src and dst found in more than one VPC configs - error
		return configsMap.matchMoreThanOneCfgErr(src, dst, configsWithSrcDstNode)
	}
	return nil, nil, nil, noInternalIP, nil
}

// no match for both src and dst in any of the cfgs: internalNoConnectedVSI > internalNotWithinSubnetsAddr > noValidInputEr
// prioritize err msg for an input (src/dst) not found in any cfg; if both prioritize src err msg
func noMatchErr(srcFoundSomeCfg, dstFoundSomeCfg bool, errMsgInternalNoConnectedVSI, errMsgInternalNotWithinSubnet,
	errMsgNoValidSrc, errMsgNoValidDst error) (vpcConfig *VPCConfig,
	srcNodes, dstNodes []Node, isSrcDstInternalIP srcDstInternalAddr, err error) {
	noInternalIP := srcDstInternalAddr{false, false}
	switch {
	case errMsgInternalNoConnectedVSI != nil:
		return nil, nil, nil, noInternalIP, errMsgInternalNoConnectedVSI
	case errMsgInternalNotWithinSubnet != nil:
		return nil, nil, nil, noInternalIP, errMsgInternalNotWithinSubnet
	default:
		// prioritize err msg for an input (src/dst) not found in any cfg; if both prioritize src err msg
		switch {
		case !srcFoundSomeCfg:
			return nil, nil, nil, noInternalIP, errMsgNoValidSrc
		case !dstFoundSomeCfg:
			return nil, nil, nil, noInternalIP, errMsgNoValidDst
		default: // src found some cfg, dst found some cfg but not in the same cfg
			return nil, nil, nil, noInternalIP, errMsgNoValidSrc
		}
	}
}

// match for both src and dst in more than one cfg
func (configsMap MultipleVPCConfigs) matchMoreThanOneCfgErr(src, dst string,
	configsWithSrcDstNode map[string]srcAndDstNodes) (vpcConfig *VPCConfig,
	srcNodes, dstNodes []Node, isSrcDstInternalIP srcDstInternalAddr, err error) {
	matchConfigs := make([]string, len(configsWithSrcDstNode))
	i := 0
	for cfgID := range configsWithSrcDstNode {
		matchConfigs[i] = configsMap[cfgID].VPC.Name()
		i++
	}
	sort.Strings(matchConfigs)
	return nil, nil, nil, srcDstInternalAddr{false, false},
		fmt.Errorf("src: %s and dst: %s found in more than one config: %s",
			src, dst, strings.Join(matchConfigs, ","))
}

// GetConnectionSet TODO: handle also input ICMP properties (type, code) as input args
// translates explanation args to a connection set
func (e *ExplanationArgs) GetConnectionSet() *common.ConnectionSet {
	if e.protocol == "" {
		return nil
	}
	connection := common.NewConnectionSet(false)
	if common.ProtocolStr(e.protocol) == common.ProtocolICMP {
		connection.AddICMPConnection(common.MinICMPtype, common.MaxICMPtype,
			common.MinICMPcode, common.MaxICMPcode)
	} else {
		connection.AddTCPorUDPConn(common.ProtocolStr(e.protocol), e.srcMinPort,
			e.srcMaxPort, e.dstMinPort, e.dstMaxPort)
	}

	return connection
}

// given src and dst input and a VPCConfigs finds the []nodes they represent in the config
// src/dst may refer to:
// 1. VSI by UID or name; in this case we consider the network interfaces of the VSI
// 2. Internal IP address or cidr; in this case we consider the vsis in that address range
// 3. external IP address or cidr
func (c *VPCConfig) srcDstInputToNodes(srcName, dstName string, isMultiVPCConfig bool) (srcNodes,
	dstNodes []Node, isSrcDstInternalIP srcDstInternalAddr, errType int, err error) {
	var isSrcInternalIP, isDstInternalIP bool
	noInternalIP := srcDstInternalAddr{false, false}
	var errSrc, errDst error
	var errSrcType, errDstType int
	srcNodes, isSrcInternalIP, errSrcType, errSrc = c.getSrcOrDstInputNode(srcName, "src", isMultiVPCConfig)
	dstNodes, isDstInternalIP, errDstType, errDst = c.getSrcOrDstInputNode(dstName, "dst", isMultiVPCConfig)
	switch {
	case errSrcType > errDstType: // src's error is of severity larger than dst's error;
		// this implies src has an error (dst may have an error and may not have an error)
		return srcNodes, dstNodes, noInternalIP, errSrcType, errSrc
	case errDstType > errSrcType: // same as above src <-> dst
		return srcNodes, dstNodes, noInternalIP, errDstType, errDst
	default: // both of the same severity, could be no error
		if errSrc != nil { // if an error, prioritize src
			return srcNodes, dstNodes, noInternalIP, errSrcType, errSrc
		}
	}
	// both src and dst are legal
	// only one of src/dst may be external; there could be multiple nodes only if external
	if !srcNodes[0].IsInternal() && !dstNodes[0].IsInternal() {
		return srcNodes, dstNodes, noInternalIP, fatalErr,
			fmt.Errorf("both src %v and dst %v are external", srcName, dstName)
	}
	return srcNodes, dstNodes, srcDstInternalAddr{isSrcInternalIP, isDstInternalIP}, noErr, nil
}

// given a VPCConfig and a string looks for the VSI/Internal IP/External address it presents,
// as described above
func (c *VPCConfig) getSrcOrDstInputNode(name, srcOrDst string, isMultiVPCConfig bool) (nodes []Node,
	internalIP bool, errType int, err error) {
	outNodes, isInternalIP, errType1, err1 := c.getNodesFromInputString(name, isMultiVPCConfig)
	if err1 != nil {
		return nil, false, errType1, fmt.Errorf("illegal %v: %v", srcOrDst, err1.Error())
	}
	if len(outNodes) == 0 {
		return nil, false, noValidInputErr, fmt.Errorf(noValidInputMsg)
	}
	return outNodes, isInternalIP, noErr, nil
}

// given a VPCConfig and a string cidrOrName representing a vsi or internal/external
// cidr/address returns the corresponding node(s) and a bool which is true iff
// cidrOrName is an internal address (and the nodes are its network interfaces)
func (c *VPCConfig) getNodesFromInputString(cidrOrName string, isMultiVPCConfig bool) (nodes []Node,
	internalIP bool, errType int, err error) {
	// 1. cidrOrName references vsi
	vsi, errType1, err1 := c.getNodesOfVsi(cidrOrName)
	if err1 != nil {
		return nil, false, errType1, err1
	}
	if vsi != nil {
		return vsi, false, noErr, nil
	}
	// cidrOrName, if legal, references an address.
	// 2. cidrOrName references an ip address
	ipBlock, err2 := ipblock.FromCidrOrAddress(cidrOrName)
	if err2 != nil {
		// the input is not a legal cidr or IP address, which in this stage means it is not a
		// valid presentation for src/dst. Lint demands that an error is returned here
		return nil, false, noValidInputErr,
			fmt.Errorf("%s %s", cidrOrName, noValidInputMsg)
	}
	// the input is a legal cidr or IP address
	return c.getNodesFromAddress(cidrOrName, ipBlock, isMultiVPCConfig)
}

// getNodesOfVsi gets a string name or UID of VSI, and
// returns the list of all nodes within this vsi
func (c *VPCConfig) getNodesOfVsi(vsi string) ([]Node, int, error) {
	var nodeSetWithVsi NodeSet
	for _, nodeSet := range c.NodeSets {
		// currently assuming c.NodeSets consists of VSIs or VPE
		if nodeSet.Name() == vsi || nodeSet.UID() == vsi {
			if nodeSetWithVsi != nil {
				return nil, fatalErr, fmt.Errorf("in %s there is more than one resource (%s, %s) with the given input string %s. "+
					"can not determine which resource to analyze. consider using unique names or use input UID instead",
					c.VPC.Name(), nodeSetWithVsi.UID(), nodeSet.UID(), vsi)
			}
			nodeSetWithVsi = nodeSet
		}
	}
	if nodeSetWithVsi == nil {
		return nil, noErr, nil
	}
	return nodeSetWithVsi.Nodes(), noErr, nil
}

// getNodesFromAddress gets a string and IPBlock that represents a cidr or IP address
// and returns the corresponding node(s)and a bool which is true iff ipOrCidr is an internal address
// (and the nodes are its network interfaces). Specifically:
//  1. If it represents a cidr which is both internal and external, returns an error
//  2. If it presents an external address, returns external addresses nodes and false
//  3. If it contains internal address not within the address range of the vpc's, subnets,
//     returns an error
//  4. If it presents an internal address, return connected network interfaces if any and true,
//  5. If none of the above holds, return nil
//
// todo: 4 - replace subnet's address range in vpc's address prefix
func (c *VPCConfig) getNodesFromAddress(ipOrCidr string, inputIPBlock *ipblock.IPBlock, isMultiVPCConfig bool) (nodes []Node,
	internalIP bool, errType int, err error) {
	// 1.
	_, publicInternet, err1 := getPublicInternetIPblocksList()
	if err1 != nil { // should never get here. If still gets here - severe error, quit with err msg
		return nil, false, fatalErr, err1
	}
	isExternal := !inputIPBlock.Intersect(publicInternet).IsEmpty()
	isInternal := !inputIPBlock.ContainedIn(publicInternet)
	if isInternal && isExternal {
		return nil, false, fatalErr,
			fmt.Errorf("%s contains both external and internal addresses which is not supported. "+
				"src, dst should be external *or* internal address", ipOrCidr)
	}
	// 2.
	if isExternal {
		nodes, errType, err = c.getCidrExternalNodes(inputIPBlock)
		if err != nil { // should never get here.
			return nil, false, errType, err
		}
		return nodes, false, noErr, nil

		// internal address
	} else if isInternal {
		// 3.
		vpcAP := c.VPC.AddressRange()
		if !inputIPBlock.ContainedIn(vpcAP) {
			errMsgPrefix := fmt.Sprintf("internal address %s not within", ipOrCidr)
			if !isMultiVPCConfig {
				return nil, false, internalNotWithinSubnetsAddr,
					fmt.Errorf("%s the vpc %s subnets' address range %s",
						errMsgPrefix, c.VPC.Name(), vpcAP.ToIPRanges())
			}
			return nil, false, internalNotWithinSubnetsAddr,
				fmt.Errorf("%s any of the VPC's subnets' address range", errMsgPrefix)
		}
	}
	// 4.
	networkInterfaces := c.getNodesWithinInternalAddress(inputIPBlock)
	// a given internal address within subnets' addr should have vsi connected to it
	if len(networkInterfaces) == 0 {
		if !isMultiVPCConfig {
			return nil, true, fatalErr, fmt.Errorf("no network interfaces are connected to %s in %s", ipOrCidr, c.VPC.Name())
		}
		return nil, true, fatalErr, fmt.Errorf("no network interfaces are connected to %s in any of the VPCs", ipOrCidr)
	}
	return networkInterfaces, true, noErr, nil
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

// getNodesWithinInternalAddress gets input IPBlock
// and returns the list of all internal nodes (should be VSI) within address
func (c *VPCConfig) getNodesWithinInternalAddress(inputIPBlock *ipblock.IPBlock) (networkInterfaceNodes []Node) {
	networkInterfaceNodes = []Node{}
	for _, node := range c.Nodes {
		if node.IsInternal() && node.IPBlock().ContainedIn(inputIPBlock) {
			networkInterfaceNodes = append(networkInterfaceNodes, node)
		}
	}
	return networkInterfaceNodes
}
