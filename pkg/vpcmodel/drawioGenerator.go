package vpcmodel

import (
	"fmt"
	"reflect"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
)

// DrawioResourceIntf is the interface of all the resources that are converted to a drawio treeNodes
type DrawioResourceIntf interface {
	GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface
	IsExternal() bool
	ShowOnSubnetMode() bool
}

// DrawioGenerator is the struct that generate the drawio tree.
// its main interface is:
// 1. TreeNode() - generate and returns the drawio tree node of a resource
// 2. the constructor - generate the treeNodes that does not represent a specific resource
// (the constructor creates the publicNetwork tree node, and the Cloud TreeNode)
// the rest of the interface i getters:
// Network(), PublicNetwork(), Cloud()
// returns the tree nodes which are created at the constructor
// please notice:
// creating the cloud treeNode is vendor specific (IBM, aws...).
// currently, the input that distinguish between the vendors is the cloudName, which is provided to NewDrawioGenerator() as parameter.
// we might later give as parameters more information to create the cloud, or create the cloud at the specific pkg.
type DrawioGenerator struct {
	network       *drawio.NetworkTreeNode
	publicNetwork *drawio.PublicNetworkTreeNode
	cloud         *drawio.CloudTreeNode
	treeNodes     map[DrawioResourceIntf]drawio.TreeNodeInterface
	EndpointElems map[common.SetAsKey]drawio.TreeNodeInterface
}

func NewDrawioGenerator(cloudName string) *DrawioGenerator {
	// creates the top of the tree node - treeNodes that does not represent a specific resource.
	gen := &DrawioGenerator{}
	gen.network = drawio.NewNetworkTreeNode()
	gen.publicNetwork = drawio.NewPublicNetworkTreeNode(gen.network)
	gen.cloud = drawio.NewCloudTreeNode(gen.network, cloudName)
	gen.treeNodes = map[DrawioResourceIntf]drawio.TreeNodeInterface{}
	gen.EndpointElems = map[common.SetAsKey]drawio.TreeNodeInterface{}
	return gen
}
func (gen *DrawioGenerator) Network() *drawio.NetworkTreeNode             { return gen.network }
func (gen *DrawioGenerator) PublicNetwork() *drawio.PublicNetworkTreeNode { return gen.publicNetwork }
func (gen *DrawioGenerator) Cloud() *drawio.CloudTreeNode                 { return gen.cloud }

func (gen *DrawioGenerator) TreeNode(res DrawioResourceIntf) drawio.TreeNodeInterface {
	if gen.treeNodes[res] == nil {
		gen.treeNodes[res] = res.GenerateDrawioTreeNode(gen)
	}
	return gen.treeNodes[res]
}

// ////////////////////////////////////////////////////////////////////////////////////////////////////////////
// implementations of the GenerateDrawioTreeNode() for resource defined in vpcmodel:

func (exn *ExternalNetwork) GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface {
	return drawio.NewInternetTreeNode(gen.PublicNetwork(), exn.CidrStr)
}
func (exn *ExternalNetwork) ShowOnSubnetMode() bool     { return true }
func (g *groupedEndpointsElems) ShowOnSubnetMode() bool { return true }
func (g *groupedExternalNodes) ShowOnSubnetMode() bool  { return true }
func (e *edgeInfo) ShowOnSubnetMode() bool              { return true }

func (g *groupedEndpointsElems) GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface {
	k := common.FromList[EndpointElem](*g).AsKey()
	if len(*g) == 1 {
		return gen.TreeNode((*g)[0])
	}
	if tn, ok := gen.EndpointElems[k]; ok {
		return tn
	}
	if gen.TreeNode((*g)[0]).IsSquare() && gen.TreeNode((*g)[0]).(drawio.SquareTreeNodeInterface).IsSubnet() {
		groupedSubnetsTNs := make([]drawio.SquareTreeNodeInterface, len(*g))
		for i, node := range *g {
			groupedSubnetsTNs[i] = gen.TreeNode(node).(drawio.SquareTreeNodeInterface)
		}
		vpcTn := groupedSubnetsTNs[0].Parent().Parent().(*drawio.VpcTreeNode)
		gen.EndpointElems[k] = drawio.GroupedSubnetsSquare(vpcTn, groupedSubnetsTNs)
	} else {
		groupedIconsTNs := make([]drawio.IconTreeNodeInterface, len(*g))
		for i, node := range *g {
			groupedIconsTNs[i] = gen.TreeNode(node).(drawio.IconTreeNodeInterface)
		}
		subnetTn := groupedIconsTNs[0].Parent().(*drawio.SubnetTreeNode)
		gen.EndpointElems[k] = drawio.NewGroupSquareTreeNode(subnetTn, groupedIconsTNs)
	}
	return gen.EndpointElems[k]
}

func (g *groupedExternalNodes) GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface {
	if len(*g) == 1 {
		return gen.TreeNode((*g)[0])
	}
	tooltip := []string{}
	for _, n := range *g {
		tooltip = append(tooltip, n.CidrStr)
	}
	name := "Various IP ranges"
	if all, _ := isEntirePublicInternetRange(*g); all {
		name = publicInternetNodeName
	}
	tn := drawio.NewInternetTreeNode(gen.PublicNetwork(), name)
	tn.SetTooltip(tooltip)
	return tn
}

func (e *edgeInfo) GenerateDrawioTreeNode(gen *DrawioGenerator) drawio.TreeNodeInterface {
	srcTn := gen.TreeNode(e.src)
	dstTn := gen.TreeNode(e.dst)
	return drawio.NewConnectivityLineTreeNode(gen.Network(), srcTn, dstTn, e.directed, e.label)
}

///////////////////////////////////////////////////////////////////////

func (d *DrawioOutputFormatter) lookForCliques() {
	type edgeKey struct {
		src   EndpointElem
		dst   EndpointElem
		label string
	}
	type labelKey struct {
		src EndpointElem
		dst EndpointElem
	}
	groupsScore := map[common.SetAsKey]int{}
	groups := map[common.SetAsKey][]EndpointElem{}
	representedGroups := map[common.SetAsKey]EndpointElem{}
	selfLoops := map[common.SetAsKey][]EndpointElem{}

	allConns := map[edgeKey]bool{}
	connLabels := map[labelKey]string{}

	for _, vpcConn := range d.conns {
		for _, line := range vpcConn.GroupedLines {
			if line.src.IsExternal() || line.dst.IsExternal() {
				continue
			}
			src, dst := line.src, line.dst
			srcs := []EndpointElem{line.src}
			dsts := []EndpointElem{line.dst}
			if reflect.TypeOf((srcs)[0]).Elem() == reflect.TypeOf(groupedEndpointsElems{}) {
				srcs = []EndpointElem(*(srcs)[0].(*groupedEndpointsElems))
			}
			if reflect.TypeOf((dsts)[0]).Elem() == reflect.TypeOf(groupedEndpointsElems{}) {
				dsts = []EndpointElem(*(dsts)[0].(*groupedEndpointsElems))
			}
			if common.FromList[EndpointElem](srcs).AsKey() == common.FromList[EndpointElem](dsts).AsKey() {
				selfLoops[common.FromList[EndpointElem](srcs).AsKey()] = srcs
			}

			for _, s := range srcs {
				for _, d := range dsts {
					allConns[edgeKey{s, d, line.ConnLabel()}] = true
					connLabels[labelKey{s, d}] = line.ConnLabel()
				}
			}
			for _, g := range [][]EndpointElem{srcs, dsts, append(dsts, srcs...)} {
				if len(g) > 1 {
					groupsScore[common.FromList[EndpointElem](g).AsKey()] += 1
					groups[common.FromList[EndpointElem](g).AsKey()] = g
				}
			}
			if len(srcs) > 1 {
				representedGroups[common.FromList[EndpointElem](srcs).AsKey()] = src
			}
			if len(dsts) > 1 {
				representedGroups[common.FromList[EndpointElem](dsts).AsKey()] = dst
			}
		}
	}

	for gk, v := range groupsScore {
		g := groups[gk]
		if v < 3 {
			continue
		}
		l, ok := connLabels[labelKey{g[0], g[1]}]
		if !ok {
			continue
		}
		isClique := true
		for _, e1 := range g {
			for _, e2 := range g {
				if e1 != e2 && !allConns[edgeKey{e1, e2, l}] {
					isClique = false
				}
			}
		}
		if isClique {
			if _, ok := representedGroups[gk]; ok {
				if _, ok := selfLoops[gk]; !ok {
					d.cliques[gk] = representedGroups[gk]
				}
			}
		}
	}

	for _, vpcConn := range d.conns {
		for _, line := range vpcConn.GroupedLines {
			if line.src.IsExternal() || line.dst.IsExternal() {
				continue
			}
			srcs := []EndpointElem{line.src}
			dsts := []EndpointElem{line.dst}
			if reflect.TypeOf((srcs)[0]).Elem() == reflect.TypeOf(groupedEndpointsElems{}) {
				srcs = []EndpointElem(*(srcs)[0].(*groupedEndpointsElems))
			}
			if reflect.TypeOf((dsts)[0]).Elem() == reflect.TypeOf(groupedEndpointsElems{}) {
				dsts = []EndpointElem(*(dsts)[0].(*groupedEndpointsElems))
			}
			lk := common.FromList[EndpointElem](append(dsts, srcs...)).AsKey()
			for ck, _ := range d.cliques {
				if lk == ck {
					d.edgeToIgnore = append(d.edgeToIgnore, line)
				}
			}

		}
	}
	for ck, clique := range d.cliques {
		srcTn := d.gen.TreeNode(clique)
		drawio.NewConnectivityLineTreeNode(d.gen.Network(), srcTn, srcTn, false, "")
		fmt.Println("a Clique ", ck)
	}
}
