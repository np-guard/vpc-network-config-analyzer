package drawio

type IconTreeNodeInterface interface {
	TreeNodeInterface
	RouterID() uint
	// TODO - support multi GSs
	SG() SquareTreeNodeInterface
	setSG(SquareTreeNodeInterface)
	allocateNewRouteOffset() int
	IsVSI() bool
	IsNI() bool
	IsGroupingPoint() bool
	SetTooltip(tooltip []string)
	HasTooltip() bool
	Tooltip() string
	IsGateway() bool
	absoluteRouterGeometry() (int, int)
	IconSize() int
	hasMiniIcon() bool
}

type abstractIconTreeNode struct {
	abstractTreeNode
	nRouterOffset int
	sg            SquareTreeNodeInterface
	tooltip       []string
}

func newAbstractIconTreeNode(parent SquareTreeNodeInterface, name string) abstractIconTreeNode {
	return abstractIconTreeNode{abstractTreeNode: newAbstractTreeNode(parent, name)}
}

func (tn *abstractIconTreeNode) SG() SquareTreeNodeInterface      { return tn.sg }
func (tn *abstractIconTreeNode) setSG(sg SquareTreeNodeInterface) { tn.sg = sg }
func (tn *abstractIconTreeNode) IsIcon() bool                     { return true }
func (tn *abstractIconTreeNode) IsVSI() bool                      { return false }
func (tn *abstractIconTreeNode) IsGateway() bool                  { return false }
func (tn *abstractIconTreeNode) IsNI() bool                       { return false }
func (tn *abstractIconTreeNode) IsGroupingPoint() bool            { return false }
func (tn *abstractIconTreeNode) SetTooltip(tooltip []string)      { tn.tooltip = tooltip }
func (tn *abstractIconTreeNode) HasTooltip() bool                 { return len(tn.tooltip) > 0 }
func (tn *abstractIconTreeNode) Tooltip() string                  { return labels2Table(tn.tooltip) }
func (tn *abstractIconTreeNode) IconSize() int                    { return iconSize }
func (tn *abstractIconTreeNode) hasMiniIcon() bool                { return false }
func (tn *abstractIconTreeNode) MiniIconID() uint                 { return tn.id + miniIconID }

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
	return absoluteGeometry(tn)
}

// ///////////////////////////////////////////
type NITreeNode struct {
	abstractIconTreeNode
	floatingIP string
	vsi        string
}

func NewNITreeNode(parent SquareTreeNodeInterface, name string) *NITreeNode {
	ni := NITreeNode{abstractIconTreeNode: newAbstractIconTreeNode(parent, name)}
	parent.addIconTreeNode(&ni)
	return &ni
}

func (tn *NITreeNode) FipID() uint       { return tn.id + niFipID }
func (tn *NITreeNode) setVsi(vsi string) { tn.vsi = vsi }
func (tn *NITreeNode) hasMiniIcon() bool { return tn.vsi != "" }
func (tn *NITreeNode) SetFIP(fip string) { tn.floatingIP = fip }
func (tn *NITreeNode) Fip() string       { return tn.floatingIP }
func (tn *NITreeNode) HasFip() bool      { return tn.Fip() != "" }
func (tn *NITreeNode) RouterID() uint    { return tn.FipID() }
func (tn *NITreeNode) IsNI() bool        { return true }
func (tn *NITreeNode) Label() string     { return labels2Table([]string{tn.name, tn.vsi}) }

func (tn *NITreeNode) absoluteRouterGeometry() (x, y int) {
	x, y = absoluteGeometry(tn)
	return x + fipXOffset, y + fipYOffset
}

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
func (tn *ResIPTreeNode) Label() string     { return labels2Table([]string{tn.name, tn.vpe}) }

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

func GroupNIsWithVSI(parent SquareTreeNodeInterface, name string, nis []TreeNodeInterface) {
	switch {
	case len(nis) == 1:
		nis[0].(*NITreeNode).setVsi(name)
	case len(nis) > 1:
		vsi := newVsiTreeNode(parent, name, nis)
		for _, ni := range nis {
			newLogicalLineTreeNode(parent, vsi, ni.(IconTreeNodeInterface))
		}
	}
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

func GroupResIPsWithVpe(parent SquareTreeNodeInterface, name string, resIPs []TreeNodeInterface) {
	switch {
	case len(resIPs) == 1:
		resIPs[0].(*ResIPTreeNode).setVpe(name)
	case len(resIPs) > 1:
		vpe := newVpeTreeNode(parent, name, resIPs)
		for _, resIP := range resIPs {
			newLogicalLineTreeNode(parent, vpe, resIP.(IconTreeNodeInterface))
		}
	}
}

func newVpeTreeNode(parent SquareTreeNodeInterface, name string, resIPs []TreeNodeInterface) *VpeTreeNode {
	vpe := &VpeTreeNode{abstractIconTreeNode: newAbstractIconTreeNode(parent, name), resIPs: resIPs}
	parent.addIconTreeNode(vpe)
	return vpe
}

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
