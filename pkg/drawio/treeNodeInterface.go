/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package drawio

import (
	"slices"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

/////////////////////////////////////////////////////////////
// the drawio has three kinds of elements:
// 1. squares (vpcs, zones, sgs, subnets...)
// 2. icons (NIs, VSIs, users ...)
// 3. lines (connectivity, NI===VSI )
//
// The connectivity map is a tree of these elements:
// the root is the network, it has vpcs, icons and connectors as children
// vpc has zones, sg and icons as children
// zones has subnets and icons as children
// sg has icons as children
// subnets has icons as children
// (an exception: one icon can be hold by a sg and a subnet)
//
// The tree is implemented using nodes pointing to each other
// Each element in this tree is a TreeNode.
//
// TreeNode implementation overview:
// TreeNodeInterface is the basic interface, implemented by all TreeNodes.
// SquareTreeNodeInterface contains TreeNodeInterface, implemented by all square TreeNodes (vpcs, zones, sgs, subnets...).
// IconTreeNodeInterface contains TreeNodeInterface, implemented by all icons TreeNodes (NIs, VSIs, users ...).
// LineTreeNodeInterface contains TreeNodeInterface, implemented by all line TreeNodes. (connectivity, NI===VSI )
//
// abstractTreeNode is the basic struct implementing a TreeNode.
// the structs abstractSquareTreeNode, abstractIconTreeNode, abstractLineTreeNode contain abstractTreeNode
// All structs representing a Square (VpcTreeNode, ZoneTreeNode, SubnetTreeNode...) contain abstractSQuareTreeNode
// All structs representing an icons (NITreeNode, GatewayTreeNode, UserTreeNode...) contain abstractIconTreeNode
// All structs representing a line (LogicalLineTreeNode, ConnectivityTreeNode) contain abstractLineTreeNode

// TreeNode main information that a TreeNode holds is:
// 1. information about the tree (its parents, its children)
// 2. information to be used in the drawio template

type TreeNodeInterface interface {
	ID() uint
	TextID() uint
	RouterID() uint
	X() int
	Y() int
	Height() int
	Width() int
	setXY(x, y int)
	setWH(w, h int)
	labels() []string
	Kind() string
	SetKind(string)

	DrawioParent() TreeNodeInterface
	Parent() TreeNodeInterface
	Location() *Location

	setParent(TreeNodeInterface)
	setLocation(location *Location)
	NotShownInDrawio() bool
	SetNotShownInDrawio()
	setID()

	/////////////////////////////
	IsLine() bool
	IsIcon() bool
	IsSquare() bool

	children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface)
}

// //////////////////////////////////////////////
func setGeometry(tn TreeNodeInterface) {
	if tn.IsIcon() {
		calculateIconGeometry(tn.(IconTreeNodeInterface))
	} else if tn.IsSquare() {
		calculateSquareGeometry(tn.(SquareTreeNodeInterface))
	}
}

// /////////////////////////////////////////////////////////////////////
// getSubTreeNodes() - return all the nodes in the sub tree

func getSubTreeNodes(tn TreeNodeInterface) (
	squares []SquareTreeNodeInterface,
	icons []IconTreeNodeInterface,
	lines []LineTreeNodeInterface) {
	for _, child := range joinTnsLists(tn.children()) {
		subSquares, subIcons, subLines := getSubTreeNodes(child)
		squares = append(squares, subSquares...)
		icons = append(icons, subIcons...)
		lines = append(lines, subLines...)
	}
	switch {
	case tn.IsSquare():
		squares = append(squares, tn.(SquareTreeNodeInterface))
	case tn.IsIcon():
		icons = append(icons, tn.(IconTreeNodeInterface))
	case tn.IsLine():
		lines = append(lines, tn.(LineTreeNodeInterface))
	}
	// remove duplications:
	squares = common.FromList(squares).AsList()
	icons = common.FromList(icons).AsList()
	lines = common.FromList(lines).AsList()
	return squares, icons, lines
}

// functions getAll* are convenient interface for getSubTreeNodes()
func getAllNodes(tn TreeNodeInterface) []TreeNodeInterface {
	return joinTnsLists(getSubTreeNodes(tn))
}
func getAllSquares(tn TreeNodeInterface) []SquareTreeNodeInterface {
	squares, _, _ := getSubTreeNodes(tn)
	return squares
}
func getAllIcons(tn TreeNodeInterface) []IconTreeNodeInterface {
	_, icons, _ := getSubTreeNodes(tn)
	return icons
}
func getAllLines(tn TreeNodeInterface) []LineTreeNodeInterface {
	_, _, lines := getSubTreeNodes(tn)
	return lines
}

func getAllSquaresAsTNs(tn TreeNodeInterface) []TreeNodeInterface {
	return joinTnsLists(getAllSquares(tn), nil, nil)
}
func getAllIconsAsTNs(tn TreeNodeInterface) []TreeNodeInterface {
	return joinTnsLists(nil, getAllIcons(tn), nil)
}
func getAllLinesAsTNs(tn TreeNodeInterface) []TreeNodeInterface {
	return joinTnsLists(nil, nil, getAllLines(tn))
}

func joinTnsLists(squares []SquareTreeNodeInterface, icons []IconTreeNodeInterface, lines []LineTreeNodeInterface) []TreeNodeInterface {
	ret := make([]TreeNodeInterface, len(squares)+len(icons)+len(lines))
	for i, square := range squares {
		ret[i] = square
	}
	for i, icon := range icons {
		ret[len(squares)+i] = icon
	}
	for i, line := range lines {
		ret[len(squares)+len(icons)+i] = line
	}
	return ret
}

////////////////////////////////////////////////////////////////////////////

func locations(tns []TreeNodeInterface) []*Location {
	locations := []*Location{}
	for _, c := range tns {
		locations = append(locations, c.Location())
	}
	return locations
}

func absoluteGeometry(tn TreeNodeInterface) (x, y int) {
	if tn.DrawioParent() == nil {
		return tn.X(), tn.Y()
	}
	return tn.X() + tn.DrawioParent().Location().firstCol.x() + tn.DrawioParent().Location().xOffset,
		tn.Y() + tn.DrawioParent().Location().firstRow.y() + tn.DrawioParent().Location().yOffset
}

func joinLabels(labels []string, sep string) string {
	labelsToJoin := slices.Clone(labels)
	labelsToJoin = slices.DeleteFunc(labelsToJoin, func(s string) bool { return s == "" })
	return strings.Join(labelsToJoin, sep)
}

func treeNodeName(tn TreeNodeInterface) string {
	return joinLabels(tn.labels(), ",")
}

// uncomment writeAsJson() treeNodeAsMap() for debug of a treeNode

// func treeNodeAsMap(tn TreeNodeInterface) map[string]interface{} {
// 	res := map[string]interface{}{}
// 	squares, icons, lines := tn.children()
// 	sqs := []interface{}{}
// 	ics := []interface{}{}
// 	lns := []interface{}{}
// 	for _, s := range squares {
// 		sqs = append(sqs, treeNodeAsMap(s))
// 	}
// 	for _, s := range icons {
// 		ics = append(ics, treeNodeAsMap(s))
// 	}
// 	for _, s := range lines {
// 		lns = append(lns, treeNodeAsMap(s))
// 	}
// 	res["name"] = tn.labels()
// 	res["squares"] = sqs
// 	res["icons"] = ics
// 	res["lines"] = lns
// 	return res
// }

// func writeTreeNodeToJsonFile(tn TreeNodeInterface, outFile string) {
// 	res, _ := json.MarshalIndent(treeNodeAsMap(tn), "", "    ")
// 	os.WriteFile(outFile, []byte(res), 0o600)
// }
