package drawio

// /////////////////////////////////////////////////////////////////////
type SquareTreeNodeInterface interface {
	TreeNodeInterface
	addIconTreeNode(icon IconTreeNodeInterface)
	addLineTreeNode(line LineTreeNodeInterface)
	IconTreeNodes() []IconTreeNodeInterface
	TagID() uint
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
func (tn *abstractSquareTreeNode) TagID() uint    { return tn.id + 1 }

func (tn *abstractSquareTreeNode) setGeometry() {
	location := tn.Location()
	parentLocation := location
	if tn.Parent() != nil {
		parentLocation = tn.Parent().Location()
	}
	tn.width = location.lastCol.width() + location.lastCol.x() - location.firstCol.x()
	tn.hight = location.lastRow.hight() + location.lastRow.y() - location.firstRow.y()
	tn.x = location.firstCol.x() - parentLocation.firstCol.x()
	tn.y = location.firstRow.y() - parentLocation.firstRow.y()
}

//////////////////////////////////////////////////////////////////////////////

type NetworkTreeNode struct {
	abstractSquareTreeNode
	vpcs []SquareTreeNodeInterface
}

func NewNetworkTreeNode() *NetworkTreeNode {
	return &NetworkTreeNode{abstractSquareTreeNode: newAbstractSquareTreeNode(nil, "Public Network")}
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
func (tn *NetworkTreeNode) IsNetwork() bool { return true }

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
func (tn *VpcTreeNode) IsVPC() bool { return true }

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
func (tn *ZoneTreeNode) IsZone() bool { return true }

///////////////////////////////////////////////////////////////////////

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

func (tn *SGTreeNode) IsSG() bool { return true }

///////////////////////////////////////////////////////////////////////

type PartialSGTreeNode struct {
	abstractSquareTreeNode
}

func newPartialSGTreeNode(parent *SGTreeNode) *PartialSGTreeNode {
	// the parent of the partialSg is the zone, not the sg:
	psg := PartialSGTreeNode{newAbstractSquareTreeNode(parent.Parent(), parent.Name())}
	parent.partialSgs = append(parent.partialSgs, &psg)
	return &psg
}
func (tn *PartialSGTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return nil, tn.elements, tn.connections
}

func (tn *PartialSGTreeNode) setGeometry() {
	location := tn.Location()
	parentLocation := tn.Parent().Location()
	tn.width = location.lastCol.width() + location.lastCol.x() - location.firstCol.x() - 2*borderWidth
	tn.hight = location.lastRow.hight() + location.lastRow.y() - location.firstRow.y() - 2*borderWidth
	tn.x = location.firstCol.x() - parentLocation.firstCol.x() + borderWidth
	tn.y = location.firstRow.y() - parentLocation.firstRow.y() + borderWidth
}
func (tn *PartialSGTreeNode) IsPartialSG() bool { return true }

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
func (tn *SubnetTreeNode) IsSubnet() bool { return true }
func (tn *SubnetTreeNode) CIDR() string   { return tn.cidr }
func (tn *SubnetTreeNode) ACL() string    { return tn.acl }

////////////////////////////////////////////////////////////////////////
