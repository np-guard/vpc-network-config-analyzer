/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package drawio

// debug points are points that can be added to the drawio,
// they are used ad a debug tool for the developer of this package (aka me)
// to add a point to the canvas call addDebugPoint(), with a point having absolute values of x and y
type debugPoint struct {
	P  point
	ID uint
}

// /////////////////////////////////////////////////////////////////////
type SquareTreeNodeInterface interface {
	TreeNodeInterface
	addIconTreeNode(icon IconTreeNodeInterface)
	addLineTreeNode(line LineTreeNodeInterface)
	IconTreeNodes() []IconTreeNodeInterface
	TagID() uint
	DecoreID() uint
	IsSubnet() bool
	IsGroupingSquare() bool
	IsGroupSubnetsSquare() bool
	DebugPoints() []debugPoint
	addDebugPoint(p point)
}

type abstractSquareTreeNode struct {
	abstractTreeNode
	elements    []IconTreeNodeInterface
	connections []LineTreeNodeInterface
	debugPoints []debugPoint
}

func newAbstractSquareTreeNode(parent TreeNodeInterface, name string) abstractSquareTreeNode {
	return abstractSquareTreeNode{abstractTreeNode: newAbstractTreeNode(parent, name)}
}
func (tn *abstractSquareTreeNode) addIconTreeNode(icon IconTreeNodeInterface) {
	tn.elements = append(tn.elements, icon)
}
func (tn *abstractSquareTreeNode) addLineTreeNode(line LineTreeNodeInterface) {
	tn.connections = append(tn.connections, line)
}

func (tn *abstractSquareTreeNode) IconTreeNodes() []IconTreeNodeInterface {
	return tn.elements
}
func (tn *abstractSquareTreeNode) IsSquare() bool { return true }

func (tn *abstractSquareTreeNode) TagID() uint    { return tn.id + tagID }
func (tn *abstractSquareTreeNode) DecoreID() uint { return tn.id + decoreID }

func (tn *abstractSquareTreeNode) IsSubnet() bool             { return false }
func (tn *abstractSquareTreeNode) IsGroupingSquare() bool     { return false }
func (tn *abstractSquareTreeNode) IsGroupSubnetsSquare() bool { return false }

func (tn *abstractSquareTreeNode) DebugPoints() []debugPoint { return tn.debugPoints }
func (tn *abstractSquareTreeNode) addDebugPoint(p point) {
	tn.debugPoints = append(tn.debugPoints, debugPoint{P: p, ID: createID()})
}

func calculateSquareGeometry(tn SquareTreeNodeInterface) {
	location := tn.Location()
	if location == nil {
		return
	}
	width := location.lastCol.width() + location.lastCol.x() - location.firstCol.x() - location.xOffset - location.xEndOffset
	height := location.lastRow.height() + location.lastRow.y() - location.firstRow.y() - location.yOffset - location.yEndOffset
	x := location.firstCol.x() + location.xOffset
	y := location.firstRow.y() + location.yOffset
	if tn.DrawioParent() != nil {
		x -= tn.DrawioParent().Location().firstCol.x()
		y -= tn.DrawioParent().Location().firstRow.y()
	}
	tn.setXY(x, y)
	tn.setWH(width, height)
}

// /////////////////////////////////////////////////////////////
// NetworkTreeNode is the top of the tree. we have only one instance of it, with constant id
type NetworkTreeNode struct {
	abstractSquareTreeNode
	clouds        []SquareTreeNodeInterface
	publicNetwork SquareTreeNodeInterface
}

func NewNetworkTreeNode() *NetworkTreeNode {
	return &NetworkTreeNode{abstractSquareTreeNode: newAbstractSquareTreeNode(nil, "network")}
}
func (tn *NetworkTreeNode) NotShownInDrawio() bool { return true }

func (tn *NetworkTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	sqs := tn.clouds
	if tn.publicNetwork != nil {
		sqs = append(sqs, tn.publicNetwork)
	}
	return sqs, tn.elements, tn.connections
}

// ////////////////////////////////////////////////////////////////
type PublicNetworkTreeNode struct {
	abstractSquareTreeNode
	PublicNetworkIcon TreeNodeInterface
}

func NewPublicNetworkTreeNode(parent *NetworkTreeNode) *PublicNetworkTreeNode {
	pn := &PublicNetworkTreeNode{abstractSquareTreeNode: newAbstractSquareTreeNode(parent, "Public Network")}
	parent.publicNetwork = pn
	return pn
}
func (tn *PublicNetworkTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return []SquareTreeNodeInterface{}, tn.elements, tn.connections
}
func (tn *PublicNetworkTreeNode) NotShownInDrawio() bool { return len(tn.IconTreeNodes()) == 0 }

// ////////////////////////////////////////////////////////////////
type CloudTreeNode struct {
	abstractSquareTreeNode
	regions []SquareTreeNodeInterface
}

func NewCloudTreeNode(parent *NetworkTreeNode, name string) *CloudTreeNode {
	cloud := CloudTreeNode{abstractSquareTreeNode: newAbstractSquareTreeNode(parent, name)}
	parent.clouds = append(parent.clouds, &cloud)
	return &cloud
}
func (tn *CloudTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return tn.regions, tn.elements, tn.connections
}

// ////////////////////////////////////////////////////////////////
type RegionTreeNode struct {
	abstractSquareTreeNode
	vpcs []SquareTreeNodeInterface
}

func NewRegionTreeNode(parent *CloudTreeNode, name string) *RegionTreeNode {
	region := RegionTreeNode{abstractSquareTreeNode: newAbstractSquareTreeNode(parent, name)}
	parent.regions = append(parent.regions, &region)
	return &region
}
func (tn *RegionTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return tn.vpcs, tn.elements, tn.connections
}

// ////////////////////////////////////////////////////////////////////////////////////////
type VpcTreeNode struct {
	abstractSquareTreeNode
	zones               []SquareTreeNodeInterface
	sgs                 []SquareTreeNodeInterface
	groupSubnetsSquares []SquareTreeNodeInterface
}

func NewVpcTreeNode(parent *RegionTreeNode, name string) *VpcTreeNode {
	vpc := VpcTreeNode{abstractSquareTreeNode: newAbstractSquareTreeNode(parent, name)}
	parent.vpcs = append(parent.vpcs, &vpc)
	return &vpc
}
func (tn *VpcTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return append(append(tn.zones, tn.sgs...), tn.groupSubnetsSquares...), tn.elements, tn.connections
}

///////////////////////////////////////////////////////////////////////

type ZoneTreeNode struct {
	abstractSquareTreeNode
	subnets []SquareTreeNodeInterface
}

func NewZoneTreeNode(parent *VpcTreeNode, name string) *ZoneTreeNode {
	zone := ZoneTreeNode{abstractSquareTreeNode: newAbstractSquareTreeNode(parent, name)}
	parent.zones = append(parent.zones, &zone)
	return &zone
}
func (tn *ZoneTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return tn.subnets, tn.elements, tn.connections
}

// /////////////////////////////////////////////////////////////////////
// SGTreeNode is not shown in the drawio file.
// since NIs sharing the same SG will not always be next to each other, one SG will be split to more than one squares.
// there squares are represented by PartialSGTreeNode. their parent in the tree is the SGTreeNode, but the parent in the drawio is the zone.
type SGTreeNode struct {
	abstractSquareTreeNode
	partialSgs []SquareTreeNodeInterface
}

func NewSGTreeNode(parent *VpcTreeNode, name string) *SGTreeNode {
	sg := SGTreeNode{abstractSquareTreeNode: newAbstractSquareTreeNode(parent, name)}
	parent.sgs = append(parent.sgs, &sg)
	return &sg
}
func (tn *SGTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return tn.partialSgs, tn.elements, tn.connections
}
func (tn *SGTreeNode) AddIcon(icon IconTreeNodeInterface) {
	tn.addIconTreeNode(icon)
	icon.addSG(tn)
}

func (tn *SGTreeNode) NotShownInDrawio() bool { return true }

// /////////////////////////////////////////////////////////////////////
// PartialSGTreeNode is the actual square of security group on the canvas
// PartialSGTreeNode represent one or more security groups
// for layout reasons, a security group can be represented by more than one PartialSGTreeNode
type PartialSGTreeNode struct {
	abstractSquareTreeNode
	sgs []*SGTreeNode
}

func newPartialSGTreeNode(sgs []*SGTreeNode) *PartialSGTreeNode {
	psg := PartialSGTreeNode{newAbstractSquareTreeNode(sgs[0].Parent(), ""), sgs}
	for _, sg := range sgs {
		sg.partialSgs = append(sg.partialSgs, &psg)
	}
	return &psg
}
func (tn *PartialSGTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return nil, tn.elements, tn.connections
}
func (tn *PartialSGTreeNode) labels() []string {
	labels := make([]string, len(tn.sgs))
	for i, sg := range tn.sgs {
		labels[i] = sg.name
	}
	return labels
}

func (tn *PartialSGTreeNode) Kind() string {
	kind := tn.sgs[0].Kind()
	if len(tn.sgs) > 1 {
		kind += "s"
	}
	return kind
}

/////////////////////////////////////////////////////////////////////////

type SubnetTreeNode struct {
	abstractSquareTreeNode
	groupSquares []SquareTreeNodeInterface
	cidr         string
	acl          string
	isPrivate    bool
}

func NewSubnetTreeNode(parent *ZoneTreeNode, name, cidr, acl string) *SubnetTreeNode {
	subnet := SubnetTreeNode{abstractSquareTreeNode: newAbstractSquareTreeNode(parent, name), cidr: cidr, acl: acl}
	parent.subnets = append(parent.subnets, &subnet)
	return &subnet
}

func (tn *SubnetTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return tn.groupSquares, tn.elements, tn.connections
}
func (tn *SubnetTreeNode) labels() []string {
	return []string{tn.name, tn.cidr, tn.acl}
}
func (tn *SubnetTreeNode) IsSubnet() bool { return true }
func (tn *SubnetTreeNode) SetACL(acl string) {
	tn.acl = acl
}
func (tn *SubnetTreeNode) nonGroupingIcons() []IconTreeNodeInterface {
	nis := []IconTreeNodeInterface{}
	for _, icon := range tn.elements {
		if !icon.IsGroupingPoint() {
			nis = append(nis, icon)
		}
	}
	return nis
}
func (tn *SubnetTreeNode) IsPrivate() bool             { return tn.isPrivate }
func (tn *SubnetTreeNode) SetIsPrivate(isPrivate bool) { tn.isPrivate = isPrivate }

// /////////////////////////////////////////////////////////////////////////////////////
// GroupSquareTreeNode is a tree node that represents a group of icons that share the same connectivity
// we are grouping all these icons with the group square.
// the connection of the square to another icon is done via a groupingPoint.
//
// for example, if the connectivity is the following connections:
//    1.     (i1,i2) -> (i3,i4)
//    2.     (i1,i2) -> (i4,i5)
//    3.     (i1,i2,i3) -> i6
// than we will have 4 groupSquare, each for every group (i1,i2), (i3,i4), (i4,i5), (i1,i2,i3).
// the group (i1,i2) will have two group point - one for each connectivity
// other groups will have only one grouping point
// the group square is not always shown on the drawio canvas. there are 4 kind of visibility for group square:
//     a. theSubnet - the group is all the icons in the subnet
//              - in this case, the square is not shown. the group point is on the border of the subnet
//     b. square - the group is a subset of icons of the subnet, the group will be bordered with a square.
//                the group point is on the border of the group square
//     c. innerSquare - the group is a subset of a group of square , the group will be bordered with an inner square inside a square
//     d. connectedPoint - the group can not be bordered, so it is connected with line to a grouping point

type groupSquareVisibility int

const (
	theSubnet groupSquareVisibility = iota
	square
	innerSquare
	connectedPoint
)

type GroupSquareTreeNode struct {
	abstractSquareTreeNode
	groupedIcons []IconTreeNodeInterface
	visibility   groupSquareVisibility
}

func (tn *GroupSquareTreeNode) IsGroupingSquare() bool { return true }

func (tn *GroupSquareTreeNode) NotShownInDrawio() bool {
	return tn.visibility == theSubnet || tn.visibility == connectedPoint
}
func NewGroupSquareTreeNode(parent *SubnetTreeNode, groupedIcons []IconTreeNodeInterface, name string) *GroupSquareTreeNode {
	gs := GroupSquareTreeNode{newAbstractSquareTreeNode(parent, name), groupedIcons, connectedPoint}
	parent.groupSquares = append(parent.groupSquares, &gs)
	return &gs
}
func (tn *GroupSquareTreeNode) setVisibility(visibility groupSquareVisibility) {
	tn.visibility = visibility
}
func (tn *GroupSquareTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return nil, append(tn.elements, tn.groupedIcons...), tn.connections
}

// ////////////////////////////////////////////////////////////////////////////
type GroupSubnetsSquareTreeNode struct {
	abstractSquareTreeNode
	groupedSubnets []SquareTreeNodeInterface
}

func GroupedSubnetsSquare(parent *VpcTreeNode, groupedSubnets []SquareTreeNodeInterface) SquareTreeNodeInterface {
	sameZone, sameVpc := true, true
	zone := groupedSubnets[0].Parent().(*ZoneTreeNode)
	vpc := groupedSubnets[0].Parent().Parent().(*VpcTreeNode)
	for _, subnet := range groupedSubnets {
		if zone != subnet.Parent() {
			sameZone = false
		}
		if vpc != subnet.Parent().Parent() {
			sameVpc = false
		}
	}
	if sameVpc {
		allVpcSubnets := []SquareTreeNodeInterface{}
		for _, z := range vpc.zones {
			allVpcSubnets = append(allVpcSubnets, z.(*ZoneTreeNode).subnets...)
		}
		if len(groupedSubnets) == len(allVpcSubnets) {
			return vpc
		}
	}
	if sameZone && len(groupedSubnets) == len(zone.subnets) {
		return zone
	}
	return newGroupSubnetsSquareTreeNode(parent, groupedSubnets)
}

func newGroupSubnetsSquareTreeNode(parent *VpcTreeNode, groupedSubnets []SquareTreeNodeInterface) *GroupSubnetsSquareTreeNode {
	gs := GroupSubnetsSquareTreeNode{newAbstractSquareTreeNode(parent, ""), groupedSubnets}
	parent.groupSubnetsSquares = append(parent.groupSubnetsSquares, &gs)
	return &gs
}
func (tn *GroupSubnetsSquareTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return tn.groupedSubnets, tn.elements, tn.connections
}
func (tn *GroupSubnetsSquareTreeNode) IsGroupSubnetsSquare() bool { return true }
