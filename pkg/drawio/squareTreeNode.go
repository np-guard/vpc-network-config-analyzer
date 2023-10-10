package drawio

// /////////////////////////////////////////////////////////////////////
type SquareTreeNodeInterface interface {
	TreeNodeInterface
	addIconTreeNode(icon IconTreeNodeInterface)
	addLineTreeNode(line LineTreeNodeInterface)
	IconTreeNodes() []IconTreeNodeInterface
	TagID() uint
	DecoreID() uint
	HasVSIs() bool
	setHasVSIs()
	IsGroupingSquare() bool
}

type abstractSquareTreeNode struct {
	abstractTreeNode
	elements    []IconTreeNodeInterface
	connections []LineTreeNodeInterface
	hasVSIs     bool
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

func (tn *abstractSquareTreeNode) HasVSIs() bool { return tn.hasVSIs }
func (tn *abstractSquareTreeNode) setHasVSIs() {
	tn.hasVSIs = true
	if tn.Parent() != nil && tn.Parent().IsSquare() {
		tn.Parent().(SquareTreeNodeInterface).setHasVSIs()
	}
}
func (tn *abstractSquareTreeNode) IsGroupingSquare() bool { return false }

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
}

func NewPublicNetworkTreeNode(parent *NetworkTreeNode) *PublicNetworkTreeNode {
	pn := &PublicNetworkTreeNode{abstractSquareTreeNode: newAbstractSquareTreeNode(parent, "Public\nNetwork")}
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
	vpcs []SquareTreeNodeInterface
}

func NewCloudTreeNode(parent *NetworkTreeNode, name string) *CloudTreeNode {
	cloud := CloudTreeNode{abstractSquareTreeNode: newAbstractSquareTreeNode(parent, name)}
	parent.clouds = append(parent.clouds, &cloud)
	return &cloud
}
func (tn *CloudTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return tn.vpcs, tn.elements, tn.connections
}

// ////////////////////////////////////////////////////////////////////////////////////////
type VpcTreeNode struct {
	abstractSquareTreeNode
	zones []SquareTreeNodeInterface
	sgs   []SquareTreeNodeInterface
}

func NewVpcTreeNode(parent *CloudTreeNode, name string) *VpcTreeNode {
	vpc := VpcTreeNode{abstractSquareTreeNode: newAbstractSquareTreeNode(parent, name)}
	parent.vpcs = append(parent.vpcs, &vpc)
	return &vpc
}
func (tn *VpcTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return append(tn.zones, tn.sgs...), tn.elements, tn.connections
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
func (tn *SGTreeNode) NotShownInDrawio() bool { return true }

///////////////////////////////////////////////////////////////////////

type PartialSGTreeNode struct {
	abstractSquareTreeNode
}

func newPartialSGTreeNode(parent *SGTreeNode) *PartialSGTreeNode {
	psg := PartialSGTreeNode{newAbstractSquareTreeNode(parent, parent.name)}
	parent.partialSgs = append(parent.partialSgs, &psg)
	return &psg
}
func (tn *PartialSGTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return nil, tn.elements, tn.connections
}
func (tn *PartialSGTreeNode) DrawioParent() TreeNodeInterface {
	return tn.Parent().Parent()
}

/////////////////////////////////////////////////////////////////////////

type SubnetTreeNode struct {
	abstractSquareTreeNode
	groupSquares []SquareTreeNodeInterface
	cidr         string
	acl          string
}

func NewSubnetTreeNode(parent *ZoneTreeNode, name, cidr, acl string) *SubnetTreeNode {
	subnet := SubnetTreeNode{abstractSquareTreeNode: newAbstractSquareTreeNode(parent, name), cidr: cidr, acl: acl}
	parent.subnets = append(parent.subnets, &subnet)
	return &subnet
}

func (tn *SubnetTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return tn.groupSquares, tn.elements, tn.connections
}
func (tn *SubnetTreeNode) Label() string {
	return labels2Table([]string{tn.name, tn.cidr, tn.acl})
}
func (tn *SubnetTreeNode) SetACL(acl string) {
	tn.acl = acl
}
func (tn *SubnetTreeNode) NIs() []IconTreeNodeInterface {
	nis := []IconTreeNodeInterface{}
	for _, icon := range tn.elements {
		if icon.IsNI() {
			nis = append(nis, icon)
		}
	}
	return nis
}

///////////////////////////////////////////////////////////////////////////////////////
type groupSquareVisibility int

const (
	theSubnet groupSquareVisibility = iota
	square
	innerSquare
	connectedPoint
)

type GroupSquareTreeNode struct {
	abstractSquareTreeNode
	groupies   []IconTreeNodeInterface
	visibility groupSquareVisibility
}

func (tn *GroupSquareTreeNode) IsGroupingSquare() bool { return true }

func (tn *GroupSquareTreeNode) NotShownInDrawio() bool {
	return tn.visibility == theSubnet || tn.visibility == connectedPoint
}
func NewGroupSquareTreeNode(parent *SubnetTreeNode, groupies []IconTreeNodeInterface) *GroupSquareTreeNode {
	gs := GroupSquareTreeNode{newAbstractSquareTreeNode(parent, ""), groupies, connectedPoint}
	parent.groupSquares = append(parent.groupSquares, &gs)
	return &gs
}
func (tn *GroupSquareTreeNode) setVisibility(visibility groupSquareVisibility) {
	tn.visibility = visibility
}
func (tn *GroupSquareTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return nil, append(tn.elements, tn.groupies...), tn.connections
}
