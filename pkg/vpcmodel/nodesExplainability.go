package vpcmodel

import (
	"fmt"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// rulesInLayers contains specific rules across all layers (SGLayer/NACLLayer)
type rulesInLayers map[string][]RulesInFilter

// rulesConnection contains the rules enabling a connection
type rulesConnection struct {
	ingressRules rulesInLayers
	egressRules  rulesInLayers
}

// finds the node of a given, by its name, Vsi
func (c *VPCConfig) getVsiNode(name string) Node {
	for _, node := range c.Nodes {
		// currently, supported: network interface given takes only that one.
		//  todo:   if address not given but only vsi name - take all network interfaces of that vsi
		if name == node.Name() {
			return node
		}
	}
	return nil
}

// given input cidr, gets (disjoint) external nodes I s.t.:
//  1. The union of these nodes is the cidr
//  2. Let i be a node in I and n be a node in VPCConfig.
//     i and n are either disjoint or i is contained in n
//     Note that the vpconfig nodes were chosen w.r.t. connectivity rules (SG and NACL)
//     s.t. each node either fully belongs to a rule or is disjoint to it.
//     to get nodes I as above:
//  1. Calculate the IP blocks of the nodes N
//  2. Calculate from N and the cidr block, disjoint IP blocks
//  3. Return the nodes created from each block from 2 contained in the input cidr
func (c *VPCConfig) getCidrExternalNodes(cidr string) (cidrDisjointNodes []Node, err error) {
	cidrsIPBlock := common.NewIPBlockFromCidr(cidr)
	if cidrsIPBlock == nil { // string cidr does not represent a legal cidr
		return nil, nil
	}
	cidrIPBlocks := []*common.IPBlock{cidrsIPBlock}
	// 1.
	vpcConfigNodesExternalBlock := make([]*common.IPBlock, 0)
	for _, node := range c.Nodes {
		if !node.IsExternal() {
			continue
		}
		thisNodeBlock := common.NewIPBlockFromCidr(node.Cidr())
		vpcConfigNodesExternalBlock = append(vpcConfigNodesExternalBlock, thisNodeBlock)
	}
	// 2.
	disjointBlocks := common.DisjointIPBlocks(cidrIPBlocks, vpcConfigNodesExternalBlock)
	// 3.
	cidrDisjointNodes = make([]Node, 0)
	for _, block := range disjointBlocks {
		if block.ContainedIn(cidrsIPBlock) {
			node, err1 := newExternalNode(true, block)
			if err1 != nil {
				return nil, err1
			}
			cidrDisjointNodes = append(cidrDisjointNodes, node)
		}
	}
	return cidrDisjointNodes, nil
}

// given a string or a vsi or a cidr returns the corresponding node(s)
func (c *VPCConfig) getNodesFromInput(cidrOrName string) ([]Node, error) {
	if vsi := c.getVsiNode(cidrOrName); vsi != nil {
		return []Node{vsi}, nil
	}
	return c.getCidrExternalNodes(cidrOrName)
}

// todo: group results. for now just prints each

// ExplainConnectivity todo: this will not be needed here once we connect explanbility to the cli
func (c *VPCConfig) ExplainConnectivity(srcName, dstName string) (explanation string, err error) {
	srcNodes, dstNodes, err := c.processInput(srcName, dstName)
	if err != nil {
		return "", err
	}
	// todo tmp: aggregating the explanations for now. Will have to group them
	explanationStr := ""
	for _, src := range srcNodes {
		for _, dst := range dstNodes {
			rulesOfConnection, err1 := c.getRulesOfConnection(src, dst)
			if err1 != nil {
				return "", err1
			}
			thisExplanationStr, err := rulesOfConnection.String(src, dst, c)
			if err != nil {
				return "", err
			}
			explanationStr += thisExplanationStr
		}
	}
	return explanationStr, nil
}

func (c *VPCConfig) processInput(srcName, dstName string) (srcNodes, dstNodes []Node, err error) {
	srcNodes, err = c.getNodesFromInput(srcName)
	if err != nil {
		return nil, nil, err
	}
	if len(srcNodes) == 0 {
		return nil, nil, fmt.Errorf("src %v does not represent a VSI or an external IP", srcName)
	}
	dstNodes, err = c.getNodesFromInput(dstName)
	if err != nil {
		return nil, nil, err
	}
	if len(dstNodes) == 0 {
		return nil, nil, fmt.Errorf("dst %v does not represent a VSI or an external IP", dstName)
	}
	// only one of src/dst can be external; there could be multiple nodes only if external
	if srcNodes[0].IsExternal() && dstNodes[0].IsExternal() {
		return nil, nil, fmt.Errorf("both src %v and dst %v are external", srcName, dstName)
	}
	return srcNodes, dstNodes, nil
}

func (c *VPCConfig) getFiltersEnablingRulesBetweenNodesPerDirectionAndLayer(
	src, dst Node, isIngress bool, layer string) (rules *[]RulesInFilter, err error) {
	filter := c.getFilterTrafficResourceOfKind(layer)
	if filter == nil {
		return nil, fmt.Errorf("layer %v not found in configuration", layer)
	}
	rulesOfFilter, err := filter.RulesInConnectivity(src, dst, isIngress)
	if err != nil {
		return nil, err
	}
	return &rulesOfFilter, nil
}

func (c *VPCConfig) getRulesOfConnection(src, dst Node) (rulesOfConnection *rulesConnection, err error) {
	filterLayers := []string{SecurityGroupLayer}
	rulesOfConnection = &rulesConnection{make(rulesInLayers, len(filterLayers)),
		make(rulesInLayers, len(filterLayers))}
	ingressRulesPerLayer, egressRulesPerLayer := make(rulesInLayers), make(rulesInLayers)
	for _, layer := range filterLayers {
		// ingress rules: relevant only if dst is internal
		if dst.IsInternal() {
			ingressRules, err1 := c.getFiltersEnablingRulesBetweenNodesPerDirectionAndLayer(src, dst, true, layer)
			if err1 != nil {
				return nil, err1
			}
			if len(*ingressRules) > 0 {
				ingressRulesPerLayer[layer] = *ingressRules
			}
		}

		// egress rules: relevant only is src is internal
		if src.IsInternal() {
			egressRules, err2 := c.getFiltersEnablingRulesBetweenNodesPerDirectionAndLayer(src, dst, false, layer)
			if err2 != nil {
				return nil, err2
			}
			if len(*egressRules) > 0 {
				egressRulesPerLayer[layer] = *egressRules
			}
		}
	}
	rulesOfConnection.ingressRules = ingressRulesPerLayer
	rulesOfConnection.egressRules = egressRulesPerLayer
	return rulesOfConnection, nil
}

// given that there is a connection between src to dst, gets it
// if src or dst is a node then the node is from getCidrExternalNodes,
// thus there is a node in VPCConfig that either equal to or contains it.
func (c *VPCConfig) getConnection(src, dst Node) (conn *common.ConnectionSet, err error) {
	srcForConnection, err1 := c.getContainingConfigNode(src)
	if err1 != nil {
		return nil, err1
	}
	dstForConnection, err2 := c.getContainingConfigNode(dst)
	if err2 != nil {
		return nil, err2
	}
	connectivity, err3 := c.GetVPCNetworkConnectivity(false) // computes connectivity
	if err3 != nil {
		return nil, err3
	}
	conn, ok := connectivity.AllowedConnsCombined[srcForConnection][dstForConnection]
	if !ok {
		return nil, fmt.Errorf("error: there is a connection between %v and %v, but connection computation failed",
			srcForConnection.Name(), dstForConnection.Name())
	}
	return conn, nil
}

// node is from getCidrExternalNodes, thus there is a node in VPCConfig that either equal to or contains it.
func (c *VPCConfig) getContainingConfigNode(node Node) (Node, error) {
	if !node.IsExternal() { // node is not external - nothing to do
		return node, nil
	}
	nodeIPBlock := common.NewIPBlockFromCidr(node.Cidr())
	if nodeIPBlock == nil { // string cidr does not represent a legal cidr
		return nil, fmt.Errorf("could not find IP block of external node %v", node.Name())
	}
	for _, configNode := range c.Nodes {
		if !configNode.IsExternal() {
			continue
		}
		configNodeIPBlock := common.NewIPBlockFromCidr(configNode.Cidr())
		if nodeIPBlock.ContainedIn(configNodeIPBlock) {
			return configNode, nil
		}
	}
	return nil, fmt.Errorf("could not find containing config node for %v", node.Name())
}

// todo: when there is more than just SG, add explanation when all layers are default

func (rulesOfConnection *rulesConnection) String(src, dst Node, c *VPCConfig) (string, error) {
	needEgress := src.IsInternal()
	needIngress := dst.IsInternal()
	noIngressRules := len(rulesOfConnection.ingressRules) == 0 && needIngress
	noEgressRules := len(rulesOfConnection.egressRules) == 0 && needEgress
	egressRulesStr := fmt.Sprintf("Egress Rules:\n~~~~~~~~~~~~~\n%v", rulesOfConnection.egressRules.string(c))
	ingressRulesStr := fmt.Sprintf("Ingress Rules:\n~~~~~~~~~~~~~~\n%v", rulesOfConnection.ingressRules.string(c))
	noConnection := fmt.Sprintf("No connection between %v and %v;", src.Name(), dst.Name())
	resStr := ""
	switch {
	case noIngressRules && noEgressRules:
		return fmt.Sprintf("%v connection blocked both by ingress and egress\n", noConnection), nil
	case noIngressRules:
		resStr = fmt.Sprintf("%v connection blocked by ingress\n", noConnection)
		if needEgress {
			resStr += egressRulesStr
		}
	case noEgressRules:
		resStr = fmt.Sprintf("%v connection blocked by egress\n", noConnection)
		if needIngress {
			resStr += ingressRulesStr
		}
	default: // there is a connection
		// todo: connectivity is computed for the entire network, even though we need only src-> dst
		//       this is seems the time spent here should be neglectable, not worth the effort of adding dedicated code.
		conn, err2 := c.getConnection(src, dst)
		if err2 != nil {
			return "", err2
		}
		resStr = fmt.Sprintf("The following connection exists between %v and %v: %v; its enabled by\n", src.Name(), dst.Name(), conn.String())
		if needEgress {
			resStr += egressRulesStr
		}
		if needIngress {
			resStr += ingressRulesStr
		}
	}
	return resStr, nil
}

func (rulesInLayers *rulesInLayers) string(c *VPCConfig) string {
	rulesInLayersStr := ""
	for layer, rules := range *rulesInLayers {
		filter := c.getFilterTrafficResourceOfKind(layer)
		if filter == nil {
			continue
		}
		rulesInLayersStr += layer + " Rules\n------------------------\n" +
			filter.StringRulesOfFilter(rules)
	}
	return rulesInLayersStr
}
