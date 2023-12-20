package vpcmodel

import (
	"fmt"
)

// rulesInLayers contains specific rules across all layers (SGLayer/NACLLayer)
type rulesInLayers map[string][]RulesInFilter

// RulesOfConnection contains the rules enabling a connection
type RulesOfConnection struct {
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

// ExplainConnectivity todo: this will not be needed here once we connect explanbility to the cli
// todo: add support of external network
func (c *VPCConfig) ExplainConnectivity(srcName, dstName string) (explanation string, err error) {
	src := c.getVsiNode(srcName)
	if src == nil {
		return "", fmt.Errorf("src %v does not represent a VSI", srcName)
	}
	dst := c.getVsiNode(dstName)
	if dst == nil {
		return "", fmt.Errorf("dst %v does not represent a VSI", dstName)
	}
	rulesOfConnection, err1 := c.GetRulesOfConnection(src, dst)
	if err1 != nil {
		return "", err1
	}
	return rulesOfConnection.String(src, dst, c)
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

func (c *VPCConfig) GetRulesOfConnection(src, dst Node) (rulesOfConnection *RulesOfConnection, err error) {
	filterLayers := []string{SecurityGroupLayer}
	rulesOfConnection = &RulesOfConnection{make(rulesInLayers, len(filterLayers)),
		make(rulesInLayers, len(filterLayers))}
	ingressRulesPerLayer, egressRulesPerLayer := make(rulesInLayers), make(rulesInLayers)
	for _, layer := range filterLayers {
		// ingress rules
		ingressRules, err1 := c.getFiltersEnablingRulesBetweenNodesPerDirectionAndLayer(src, dst, true, layer)
		if err1 != nil {
			return nil, err1
		}
		if len(*ingressRules) > 0 {
			ingressRulesPerLayer[layer] = *ingressRules
		}

		// egress rules
		egressRules, err2 := c.getFiltersEnablingRulesBetweenNodesPerDirectionAndLayer(src, dst, false, layer)
		if err2 != nil {
			return nil, err2
		}
		if len(*egressRules) > 0 {
			egressRulesPerLayer[layer] = *egressRules
		}
	}
	rulesOfConnection.ingressRules = ingressRulesPerLayer
	rulesOfConnection.egressRules = egressRulesPerLayer
	return rulesOfConnection, nil
}

func (rulesOfConnection *RulesOfConnection) String(src, dst Node, c *VPCConfig) (string, error) {
	noIngressRules := len(rulesOfConnection.ingressRules) == 0
	noEgressRules := len(rulesOfConnection.egressRules) == 0
	egressRulesStr := rulesOfConnection.egressRules.string(c)
	ingressRulesStr := rulesOfConnection.ingressRules.string(c)
	switch {
	case noIngressRules && noEgressRules:
		return fmt.Sprintf("No connection between %v and %v; connection blocked both by ingress and egress\n", src.Name(), dst.Name()), nil
	case noIngressRules:
		return fmt.Sprintf("No connection between %v and %v; connection blocked by ingress\n"+
			"Egress Rules:\n~~~~~~~~~~~~~~\n%v", src.Name(), dst.Name(), egressRulesStr), nil
	case noEgressRules:
		return fmt.Sprintf("No connection between %v and %v; connection blocked by egress\n"+
			"Ingress Rules:\n~~~~~~~~~~~~~\n%v", src.Name(), dst.Name(), ingressRulesStr), nil
	default: // there is a connection
		// todo: connectivity is computed for the entire network, even though we need only src-> dst
		//       this is seems the time spent here should be neglectable, not worth the effort of adding dedicated code.
		connectivity, err := c.GetVPCNetworkConnectivity(false) // computes connectivity
		if err != nil {
			return "", err
		}
		conn, ok := connectivity.AllowedConnsCombined[src][dst]
		if !ok {
			return "", fmt.Errorf("error: there is a connection between %v and %v, but connection computation failed",
				src.Name(), dst.Name())
		}
		return fmt.Sprintf("The following connection exists between %v and %v: %v; its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\n%v\n"+
			"Ingress Rules:\n~~~~~~~~~~~~~~\n%v\n", src.Name(), dst.Name(), conn.String(), egressRulesStr, ingressRulesStr), nil
	}
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
