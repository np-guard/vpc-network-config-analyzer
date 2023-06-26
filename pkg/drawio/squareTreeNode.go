package drawio

// /////////////////////////////////////////////////////////////////////
type SquareTreeNodeInterface interface {
	TreeNodeInterface
	addIconTreeNode(icon IconTreeNodeInterface)
	addLineTreeNode(line LineTreeNodeInterface)
	IconTreeNodes() []IconTreeNodeInterface
	TagID() uint
	DecoreID() uint
}

type abstractSquareTreeNode struct {
	abstractTreeNode
	elements    []IconTreeNodeInterface
	connections []LineTreeNodeInterface
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

func (tn *abstractSquareTreeNode) setGeometry() {
	location := tn.Location()
	tn.width = location.lastCol.width() + location.lastCol.x() - location.firstCol.x()
	tn.height = location.lastRow.height() + location.lastRow.y() - location.firstRow.y()
	tn.x = location.firstCol.x()
	tn.y = location.firstRow.y()
	if tn.DrawioParent().Location() != nil {
		tn.x -= tn.DrawioParent().Location().firstCol.x()
		tn.y -= tn.DrawioParent().Location().firstRow.y()
	}
}

// ////////////////////////////////////////////////////////////////
type NetworkTreeNode struct {
	abstractSquareTreeNode
	vpcs []SquareTreeNodeInterface
}

var networkParent = &rootTreeNode{}

func NewNetworkTreeNode() *NetworkTreeNode {
	return &NetworkTreeNode{abstractSquareTreeNode: newAbstractSquareTreeNode(networkParent, "Public Network")}
}
func (tn *NetworkTreeNode) DrawioParentID() uint {
	if tn.Parent() != nil {
		tn.Parent().ID()
	}
	return 1
}

func (tn *NetworkTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return tn.vpcs, tn.elements, tn.connections
}

// ////////////////////////////////////////////////////////////////////////////////////////
type VpcTreeNode struct {
	abstractSquareTreeNode
	zones []SquareTreeNodeInterface
	sgs   []SquareTreeNodeInterface
}

func NewVpcTreeNode(parent *NetworkTreeNode, name string) *VpcTreeNode {
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
func (tn *SGTreeNode) setGeometry() {}

func (tn *SGTreeNode) NotShownInDrawio() bool { return true }

///////////////////////////////////////////////////////////////////////

type PartialSGTreeNode struct {
	abstractSquareTreeNode
}

func newPartialSGTreeNode(parent *SGTreeNode) *PartialSGTreeNode {
	psg := PartialSGTreeNode{newAbstractSquareTreeNode(parent, parent.Name())}
	parent.partialSgs = append(parent.partialSgs, &psg)
	return &psg
}
func (tn *PartialSGTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return nil, tn.elements, tn.connections
}
func (tn *PartialSGTreeNode) DrawioParent() TreeNodeInterface {
	return tn.Parent().Parent()
}

func (tn *PartialSGTreeNode) setGeometry() {
	location := tn.Location()
	parentLocation := tn.DrawioParent().Location()
	tn.width = location.lastCol.width() + location.lastCol.x() - location.firstCol.x() - 2*borderWidth
	tn.height = location.lastRow.height() + location.lastRow.y() - location.firstRow.y() - 2*borderWidth
	tn.x = location.firstCol.x() - parentLocation.firstCol.x() + borderWidth
	tn.y = location.firstRow.y() - parentLocation.firstRow.y() + borderWidth
}

/////////////////////////////////////////////////////////////////////////

type SubnetTreeNode struct {
	abstractSquareTreeNode
	cidr string
	acl  string
}

func NewSubnetTreeNode(parent *ZoneTreeNode, name, cidr, acl string) *SubnetTreeNode {
	subnet := SubnetTreeNode{abstractSquareTreeNode: newAbstractSquareTreeNode(parent, name), cidr: cidr, acl: acl}
	parent.subnets = append(parent.subnets, &subnet)
	return &subnet
}

func (tn *SubnetTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return []SquareTreeNodeInterface{}, tn.elements, tn.connections
}
func (tn *SubnetTreeNode) CIDR() string { return tn.cidr }
func (tn *SubnetTreeNode) ACL() string  { return tn.acl }

////////////////////////////////////////////////////////////////////////
