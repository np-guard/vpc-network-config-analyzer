package drawio

type IconTreeNodeInterface interface {
	TreeNodeInterface
	RouterID() uint
	SG() SquareTreeNodeInterface
	allocateNewRouteOffset() int
}

type abstractIconTreeNode struct {
	abstractTreeNode
	nRouterOffset int
	sg            SquareTreeNodeInterface
}

func newAbstractIconTreeNode(parent SquareTreeNodeInterface, name string) abstractIconTreeNode {
	return abstractIconTreeNode{abstractTreeNode: newAbstractTreeNode(parent, name)}
}

func (tn *abstractIconTreeNode) SG() SquareTreeNodeInterface { return tn.sg }
func (tn *abstractIconTreeNode) IsIcon() bool                { return true }

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
func (tn *abstractIconTreeNode) setGeometry() {
	tn.x, tn.y = calculateIconGeometry(tn, tn.DrawioParent())
}

func calculateIconGeometry(tn IconTreeNodeInterface, drawioParent TreeNodeInterface) (x, y int) {
	location := tn.Location()
	parentLocation := drawioParent.Location()
	x = location.firstCol.x() - parentLocation.firstCol.x() + location.firstCol.width()/2 - iconSize/2 + location.xOffset
	y = location.firstRow.y() - parentLocation.firstRow.y() + location.firstRow.height()/2 - iconSize/2 + location.yOffset
	return x, y
}

// ///////////////////////////////////////////
type NITreeNode struct {
	abstractIconTreeNode
	floatingIP string
	vsi        string
}

func NewNITreeNode(parent SquareTreeNodeInterface, sg *SGTreeNode, name string) *NITreeNode {
	ni := NITreeNode{abstractIconTreeNode: newAbstractIconTreeNode(parent, name)}
	parent.addIconTreeNode(&ni)
	if sg != nil {
		ni.setSG(sg)
	}
	return &ni
}
func (tn *NITreeNode) setSG(sg *SGTreeNode) {
	sg.addIconTreeNode(tn)
	tn.sg = sg
}
func (tn *NITreeNode) VsiID() uint       { return tn.id + niVsiID }
func (tn *NITreeNode) FipID() uint       { return tn.id + niFipID }
func (tn *NITreeNode) TextID() uint      { return tn.id + textID }
func (tn *NITreeNode) SetVsi(vsi string) { tn.vsi = vsi }
func (tn *NITreeNode) Vsi() string       { return tn.vsi }
func (tn *NITreeNode) HasVsi() bool      { return tn.Vsi() != "" }
func (tn *NITreeNode) SetFIP(fip string) { tn.floatingIP = fip }
func (tn *NITreeNode) Fip() string       { return tn.floatingIP }
func (tn *NITreeNode) HasFip() bool      { return tn.Fip() != "" }
func (tn *NITreeNode) RouterID() uint    { return tn.FipID() }
func (tn *NITreeNode) IsNI() bool        { return true }

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
type UserTreeNode struct {
	abstractIconTreeNode
}

func NewUserTreeNode(parent SquareTreeNodeInterface, name string) *UserTreeNode {
	user := UserTreeNode{newAbstractIconTreeNode(parent, name)}
	parent.addIconTreeNode(&user)
	return &user
}
func (tn *UserTreeNode) IsUser() bool { return true }

// ///////////////////////////////////////////
type VsiTreeNode struct {
	abstractIconTreeNode
	nis []TreeNodeInterface
}

func GroupNIsWithVSI(parent SquareTreeNodeInterface, name string, nis []TreeNodeInterface) {
	switch {
	case len(nis) == 1:
		nis[0].(*NITreeNode).SetVsi(name)
	case len(nis) > 1:
		vsi := newVsiTreeNode(parent, name, nis)
		for _, ni := range nis {
			newVsiLineTreeNode(parent, vsi, ni.(*NITreeNode))
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
func (tn *VsiTreeNode) DrawioParentID() uint {
	if len(tn.GetVsiNIsSubnets()) == 1 {
		return tn.nis[0].Parent().ID()
	}
	return tn.Parent().ID()
}

func (tn *VsiTreeNode) setGeometry() {
	tn.x, tn.y = calculateIconGeometry(tn, tn.DrawioParent())
}

func (tn *VsiTreeNode) DrawioParent() TreeNodeInterface {
	if len(tn.GetVsiNIsSubnets()) == 1 {
		return tn.nis[0].Parent()
	}
	return tn.Parent()
}

func (tn *VsiTreeNode) IsVSI() bool { return true }

// ///////////////////////////////////////////
type InternetTreeNode struct {
	abstractIconTreeNode
}

func NewInternetTreeNode(parent SquareTreeNodeInterface, name string) *InternetTreeNode {
	inter := InternetTreeNode{newAbstractIconTreeNode(parent, name)}
	parent.addIconTreeNode(&inter)
	return &inter
}
func (tn *InternetTreeNode) IsInternet() bool { return true }

// ////////////////////////////////////////////////////////////////
type InternetServiceTreeNode struct {
	abstractIconTreeNode
}

func NewInternetServiceTreeNode(parent SquareTreeNodeInterface, name string) *InternetServiceTreeNode {
	inter := InternetServiceTreeNode{newAbstractIconTreeNode(parent, name)}
	parent.addIconTreeNode(&inter)
	return &inter
}
func (tn *InternetServiceTreeNode) IsInternetService() bool { return true }
