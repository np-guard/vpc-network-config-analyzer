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

func (tn *abstractSquareTreeNode) setGeometry() {
	location := tn.Location()
	if location == nil{
		return
	}
	tn.width = location.lastCol.width() + location.lastCol.x() - location.firstCol.x()
	tn.height = location.lastRow.height() + location.lastRow.y() - location.firstRow.y()
	tn.x = location.firstCol.x()
	tn.y = location.firstRow.y()
	if tn.DrawioParent() != nil {
		tn.x -= tn.DrawioParent().Location().firstCol.x()
		tn.y -= tn.DrawioParent().Location().firstRow.y()
	}
}

// /////////////////////////////////////////////////////////////
// NetworkTreeNode is the top of the tree. we have only one instance of it, with constant id
type NetworkTreeNode struct {
	abstractSquareTreeNode
	ibmClouds     []SquareTreeNodeInterface
	publicNetwork SquareTreeNodeInterface
}

func NewNetworkTreeNode() *NetworkTreeNode {
	tn := NetworkTreeNode{}
	tn.id = rootID
	return &tn
}

func (tn *NetworkTreeNode) NotShownInDrawio() bool { return true }

func (tn *NetworkTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	sqs := tn.ibmClouds
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
type IBMCloudTreeNode struct {
	abstractSquareTreeNode
	vpcs []SquareTreeNodeInterface
}

func NewIBMCloudTreeNode(parent *NetworkTreeNode) *IBMCloudTreeNode {
	cloud := IBMCloudTreeNode{abstractSquareTreeNode: newAbstractSquareTreeNode(parent, "IBM Cloud")}
	parent.ibmClouds = append(parent.ibmClouds, &cloud)
	return &cloud
}
func (tn *IBMCloudTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return tn.vpcs, tn.elements, tn.connections
}

// ////////////////////////////////////////////////////////////////////////////////////////
type VpcTreeNode struct {
	abstractSquareTreeNode
	zones []SquareTreeNodeInterface
	sgs   []SquareTreeNodeInterface
}

func NewVpcTreeNode(parent *IBMCloudTreeNode, name string) *VpcTreeNode {
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
func (tn *SubnetTreeNode) Label() string {
	return labels2Table([]string{tn.name, tn.cidr, tn.acl})
}
func (tn *SubnetTreeNode) SetACL(acl string) {
	tn.acl = acl
}
