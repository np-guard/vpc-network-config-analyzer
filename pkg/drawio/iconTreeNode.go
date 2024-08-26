/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package drawio

import "github.com/np-guard/vpc-network-config-analyzer/pkg/common"

type IconTreeNodeInterface interface {
	TreeNodeInterface
	RouterID() uint
	SGs() common.GenericSet[*SGTreeNode]
	addSG(*SGTreeNode)
	allocateNewRouteOffset() int
	IsVSI() bool
	IsGroupingPoint() bool
	SetTooltip(tooltip []string)
	HasTooltip() bool
	Tooltip() string
	IsGateway() bool
	absoluteRouterGeometry() (int, int)
	IconSize() int
	hasMiniIcon() bool
	HasFip() bool
	SetFIP(fip string)
	Fip() string
	FipID() uint
}

// both NIs ResIp and PrivateIPs are grouped by logical connection.
// Todo: we need to make inheritance, to remove duplicate code
// (for now I did minimal changes, for easier code review)

type abstractIconTreeNode struct {
	abstractTreeNode
	nRouterOffset int
	sgs           common.GenericSet[*SGTreeNode]
	tooltip       []string
	floatingIP    string
}

func newAbstractIconTreeNode(parent SquareTreeNodeInterface, name string) abstractIconTreeNode {
	return abstractIconTreeNode{
		abstractTreeNode: newAbstractTreeNode(parent, name),
		sgs:              common.GenericSet[*SGTreeNode]{}}
}

func (tn *abstractIconTreeNode) SGs() common.GenericSet[*SGTreeNode] { return tn.sgs }
func (tn *abstractIconTreeNode) addSG(sg *SGTreeNode)                { tn.sgs[sg] = true }
func (tn *abstractIconTreeNode) IsIcon() bool                        { return true }
func (tn *abstractIconTreeNode) IsVSI() bool                         { return false }
func (tn *abstractIconTreeNode) IsGateway() bool                     { return false }
func (tn *abstractIconTreeNode) IsGroupingPoint() bool               { return false }
func (tn *abstractIconTreeNode) SetTooltip(tooltip []string)         { tn.tooltip = tooltip }
func (tn *abstractIconTreeNode) HasTooltip() bool                    { return len(tn.tooltip) > 0 }
func (tn *abstractIconTreeNode) Tooltip() string                     { return joinLabels(tn.tooltip, drawioTableSep) }
func (tn *abstractIconTreeNode) IconSize() int                       { return iconSize }
func (tn *abstractIconTreeNode) hasMiniIcon() bool                   { return false }
func (tn *abstractIconTreeNode) MiniIconID() uint                    { return tn.id + miniIconID }
func (tn *abstractIconTreeNode) Height() int                         { return iconSize }
func (tn *abstractIconTreeNode) Width() int                          { return iconSize }
func (tn *abstractIconTreeNode) HasFip() bool                        { return tn.Fip() != "" }
func (tn *abstractIconTreeNode) SetFIP(fip string)                   { tn.floatingIP = fip }
func (tn *abstractIconTreeNode) Fip() string                         { return tn.floatingIP }
func (tn *abstractIconTreeNode) FipID() uint                         { return tn.id + fipID }

var offsets = []int{
	0,
	8, -8, 16, -16, 24, -24,
	4, -4, 12, -12, 20, -20,
	2, -2, 10, -10, 18, -18,
	6, -6, 14, -14, 22, -22,
}

func (tn *abstractIconTreeNode) allocateNewRouteOffset() int {
	n := tn.nRouterOffset
	tn.nRouterOffset++
	if n >= len(offsets) {
		return 0
	}
	return offsets[n]
}

func calculateIconGeometry(tn IconTreeNodeInterface) {
	location := tn.Location()
	parentLocation := tn.DrawioParent().Location()
	x := location.firstCol.x() - parentLocation.firstCol.x() + location.firstCol.width()/2 -
		tn.IconSize()/2 + location.xOffset - parentLocation.xOffset
	y := location.firstRow.y() - parentLocation.firstRow.y() + location.firstRow.height()/2 -
		tn.IconSize()/2 + location.yOffset - parentLocation.yOffset
	tn.setXY(x, y)
}
func (tn *abstractIconTreeNode) absoluteRouterGeometry() (x, y int) {
	x, y = absoluteGeometry(tn)
	if tn.HasFip() {
		x, y = x+fipXOffset, y+fipYOffset
	}
	return x, y
}

// ///////////////////////////////////////////
type NITreeNode struct {
	abstractIconTreeNode
	vsi     string
	virtual bool
}

func NewNITreeNode(parent SquareTreeNodeInterface, name string, virtual bool) *NITreeNode {
	ni := NITreeNode{abstractIconTreeNode: newAbstractIconTreeNode(parent, name), virtual: virtual}
	parent.addIconTreeNode(&ni)
	return &ni
}

func (tn *NITreeNode) setVsi(vsi string) { tn.vsi = vsi }
func (tn *NITreeNode) hasMiniIcon() bool { return tn.vsi != "" }
func (tn *NITreeNode) isVirtual() bool   { return tn.virtual }
func (tn *NITreeNode) RouterID() uint    { return tn.FipID() }
func (tn *NITreeNode) labels() []string  { return []string{tn.name, tn.vsi} }

// ///////////////////////////////////////////
type ResIPTreeNode struct {
	abstractIconTreeNode
	vpe string
}

func NewResIPTreeNode(parent SquareTreeNodeInterface, name string) *ResIPTreeNode {
	rip := ResIPTreeNode{abstractIconTreeNode: newAbstractIconTreeNode(parent, name)}
	parent.addIconTreeNode(&rip)
	return &rip
}

func (tn *ResIPTreeNode) setVpe(vpe string) { tn.vpe = vpe }
func (tn *ResIPTreeNode) hasMiniIcon() bool { return tn.vpe != "" }
func (tn *ResIPTreeNode) labels() []string  { return []string{tn.name, tn.vpe} }

// ///////////////////////////////////////////
type GatewayTreeNode struct {
	abstractIconTreeNode
}

func NewGatewayTreeNode(parent SquareTreeNodeInterface, name string) *GatewayTreeNode {
	gw := GatewayTreeNode{newAbstractIconTreeNode(parent, name)}
	parent.addIconTreeNode(&gw)
	return &gw
}
func (tn *GatewayTreeNode) IsGateway() bool { return true }

// ///////////////////////////////////////////
type TransitGatewayTreeNode struct {
	abstractIconTreeNode
}

func NewTransitGatewayTreeNode(parent SquareTreeNodeInterface, name string) *TransitGatewayTreeNode {
	tgw := TransitGatewayTreeNode{newAbstractIconTreeNode(parent, name)}
	parent.addIconTreeNode(&tgw)
	return &tgw
}

// ///////////////////////////////////////////
type InternetGatewayTreeNode struct {
	abstractIconTreeNode
}

func NewInternetGatewayTreeNode(parent SquareTreeNodeInterface, name string) *InternetGatewayTreeNode {
	igw := InternetGatewayTreeNode{newAbstractIconTreeNode(parent, name)}
	parent.addIconTreeNode(&igw)
	return &igw
}

// ///////////////////////////////////////////
type UserTreeNode struct {
	abstractIconTreeNode
}

func NewUserTreeNode(parent SquareTreeNodeInterface, name string) *UserTreeNode {
	user := UserTreeNode{newAbstractIconTreeNode(parent, name)}
	parent.addIconTreeNode(&user)
	return &user
}

// ///////////////////////////////////////////
type VsiTreeNode struct {
	abstractIconTreeNode
	nis []TreeNodeInterface
}

func GroupNIsWithVSI(parent SquareTreeNodeInterface, name string, nis []TreeNodeInterface) TreeNodeInterface {
	switch {
	case len(nis) == 1:
		nis[0].(*NITreeNode).setVsi(name)
		return nis[0]
	case len(nis) > 1:
		vsi := newVsiTreeNode(parent, name, nis)
		for _, ni := range nis {
			newLogicalLineTreeNode(parent, vsi, ni.(IconTreeNodeInterface))
		}
		return vsi
	}
	return nil
}

func newVsiTreeNode(parent SquareTreeNodeInterface, name string, nis []TreeNodeInterface) *VsiTreeNode {
	vsi := &VsiTreeNode{abstractIconTreeNode: newAbstractIconTreeNode(parent, name), nis: nis}
	parent.addIconTreeNode(vsi)
	return vsi
}

func (tn *VsiTreeNode) GetVsiNIsSubnets() map[TreeNodeInterface]bool {
	vsiSubnets := map[TreeNodeInterface]bool{}
	for _, ni := range tn.nis {
		vsiSubnets[ni.Parent()] = true
	}
	return vsiSubnets
}

func (tn *VsiTreeNode) DrawioParent() TreeNodeInterface {
	if len(tn.GetVsiNIsSubnets()) == 1 {
		return tn.nis[0].Parent()
	}
	return tn.Parent()
}

func (tn *VsiTreeNode) IsVSI() bool { return true }

// ///////////////////////////////////////////
type VpeTreeNode struct {
	abstractIconTreeNode
	resIPs []TreeNodeInterface
}

func GroupResIPsWithVpe(parent SquareTreeNodeInterface, name string, resIPs []TreeNodeInterface) TreeNodeInterface {
	switch {
	case len(resIPs) == 1:
		resIPs[0].(*ResIPTreeNode).setVpe(name)
		return resIPs[0]
	case len(resIPs) > 1:
		vpe := newVpeTreeNode(parent, name, resIPs)
		for _, resIP := range resIPs {
			newLogicalLineTreeNode(parent, vpe, resIP.(IconTreeNodeInterface))
		}
		return vpe
	}
	return nil
}

func newVpeTreeNode(parent SquareTreeNodeInterface, name string, resIPs []TreeNodeInterface) *VpeTreeNode {
	vpe := &VpeTreeNode{abstractIconTreeNode: newAbstractIconTreeNode(parent, name), resIPs: resIPs}
	parent.addIconTreeNode(vpe)
	return vpe
}

// ///////////////////////////////////////////
type LoadBalancerTreeNode struct {
	abstractIconTreeNode
	PrivateIPs []TreeNodeInterface
}

func GroupPrivateIPsWithLoadBalancer(parent SquareTreeNodeInterface, name string, privateIPs []TreeNodeInterface) *LoadBalancerTreeNode {
	loadBalancer := newLoadBalancerTreeNode(parent, name, privateIPs)
	for _, privateIP := range privateIPs {
		newLogicalLineTreeNode(parent, loadBalancer, privateIP.(IconTreeNodeInterface))
	}
	return loadBalancer
}

func newLoadBalancerTreeNode(parent SquareTreeNodeInterface, name string, privateIPs []TreeNodeInterface) *LoadBalancerTreeNode {
	loadBalancer := &LoadBalancerTreeNode{abstractIconTreeNode: newAbstractIconTreeNode(parent, name), PrivateIPs: privateIPs}
	parent.addIconTreeNode(loadBalancer)
	return loadBalancer
}

type PrivateIPTreeNode struct {
	abstractIconTreeNode
	original bool // does the private IP was originally at the config file, or is it just potential one
}

func NewPrivateIPTreeNode(parent SquareTreeNodeInterface, name string, original bool) *PrivateIPTreeNode {
	rip := PrivateIPTreeNode{abstractIconTreeNode: newAbstractIconTreeNode(parent, name)}
	parent.addIconTreeNode(&rip)
	rip.original = original
	return &rip
}

func (tn *PrivateIPTreeNode) RouterID() uint { return tn.FipID() }
func (tn *PrivateIPTreeNode) Original() bool { return tn.original }

// ///////////////////////////////////////////

// ///////////////////////////////////////////
// GroupPointTreeNode is an icon for grouping, see GroupSquareTreeNode for details
// the connection to the group will be to the group point
// a GroupPoint is holding:
// 1. the colleague - the other icon that it is connected to
// 2. the  groupedIconsConns - the connections between the groupPoint and the the groupedIcons
type GroupPointTreeNode struct {
	abstractIconTreeNode
	colleague         IconTreeNodeInterface
	groupedIconsConns []LineTreeNodeInterface
	directed          bool
	isSrc             bool
}

func (tn *GroupPointTreeNode) setColleague(colleague IconTreeNodeInterface) { tn.colleague = colleague }
func (tn *GroupPointTreeNode) getColleague() IconTreeNodeInterface          { return tn.colleague }
func (tn *GroupPointTreeNode) IconSize() int {
	if tn.hasShownSquare() {
		return groupedIconSize
	}
	return 1
}
func (tn *GroupPointTreeNode) Height() int { return tn.IconSize() }
func (tn *GroupPointTreeNode) Width() int  { return tn.IconSize() }

func (tn *GroupPointTreeNode) IsGroupingPoint() bool { return true }
func (tn *GroupPointTreeNode) hasShownSquare() bool {
	return tn.Parent().(*GroupSquareTreeNode).visibility != connectedPoint
}

func NewGroupPointTreeNode(parent SquareTreeNodeInterface,
	directed bool,
	isSrc bool,
	connName string) *GroupPointTreeNode {
	groupPoint := &GroupPointTreeNode{
		abstractIconTreeNode: newAbstractIconTreeNode(parent, ""),
		directed:             directed,
		isSrc:                isSrc,
	}
	parent.addIconTreeNode(groupPoint)
	return groupPoint
}
func (tn *GroupPointTreeNode) connectGroupedIcons() {
	for _, groupedIcon := range tn.Parent().(*GroupSquareTreeNode).groupedIcons {
		var s, d IconTreeNodeInterface = tn, groupedIcon
		// in case the GroupPoint is the src, its means we have an arrow from the tn to  its colleague.
		// so we want to add arrows from the groupIcon to the GroupPoint
		if tn.isSrc {
			s, d = groupedIcon, tn
		}
		gtn := NewConnectivityLineTreeNode(tn.DrawioParent().(SquareTreeNodeInterface), s, d, tn.directed, "")
		tn.groupedIconsConns = append(tn.groupedIconsConns, gtn)
	}
}
func (tn *GroupPointTreeNode) DrawioParent() TreeNodeInterface {
	if tn.parent.NotShownInDrawio() {
		return tn.Parent().Parent()
	}
	return tn.Parent()
}

// ///////////////////////////////////////////
type InternetTreeNode struct {
	abstractIconTreeNode
}

func NewInternetTreeNode(parent SquareTreeNodeInterface, name string) *InternetTreeNode {
	inter := InternetTreeNode{newAbstractIconTreeNode(parent, name)}
	parent.addIconTreeNode(&inter)
	return &inter
}

// ////////////////////////////////////////////////////////////////
type InternetServiceTreeNode struct {
	abstractIconTreeNode
}

func NewInternetServiceTreeNode(parent SquareTreeNodeInterface, name string) *InternetServiceTreeNode {
	inter := InternetServiceTreeNode{newAbstractIconTreeNode(parent, name)}
	parent.addIconTreeNode(&inter)
	return &inter
}
