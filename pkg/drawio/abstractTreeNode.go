package drawio

const (
	minID      = 100
	nextIDStep = 10
	niVsiID    = 1
	niFipID    = 2
	textID     = 3
	tagID      = 4
)

type abstractTreeNode struct {
	id       uint
	x        int
	y        int
	name     string
	width    int
	height   int
	parent   TreeNodeInterface
	location *Location
}

func (tn *abstractTreeNode) Name() string         { return tn.name }
func (tn *abstractTreeNode) ID() uint             { return tn.id }
func (tn *abstractTreeNode) DrawioParentID() uint { return tn.Parent().ID() }
func (tn *abstractTreeNode) X() int               { return tn.x }
func (tn *abstractTreeNode) Y() int               { return tn.y }
func (tn *abstractTreeNode) Height() int          { return tn.height }
func (tn *abstractTreeNode) Width() int           { return tn.width }

func (tn *abstractTreeNode) Location() *Location       { return tn.location }
func (tn *abstractTreeNode) Parent() TreeNodeInterface { return tn.parent }

func (tn *abstractTreeNode) setLocation(location *Location) { tn.location = location }
func (tn *abstractTreeNode) setParent(p TreeNodeInterface)  { tn.parent = p }
func (tn *abstractTreeNode) NotShownInDrawio() bool         { return false }

var idCounter uint = minID

func (tn *abstractTreeNode) setID() {
	if tn.id == 0 {
		tn.id = idCounter
		idCounter += nextIDStep
	}
}

func (tn *abstractTreeNode) IsLine() bool            { return false }
func (tn *abstractTreeNode) IsIcon() bool            { return false }
func (tn *abstractTreeNode) IsSquare() bool          { return false }
func (tn *abstractTreeNode) IsNetwork() bool         { return false }
func (tn *abstractTreeNode) IsVPC() bool             { return false }
func (tn *abstractTreeNode) IsZone() bool            { return false }
func (tn *abstractTreeNode) IsSubnet() bool          { return false }
func (tn *abstractTreeNode) IsSG() bool              { return false }
func (tn *abstractTreeNode) IsPartialSG() bool       { return false }
func (tn *abstractTreeNode) IsVSI() bool             { return false }
func (tn *abstractTreeNode) IsNI() bool              { return false }
func (tn *abstractTreeNode) IsGateway() bool         { return false }
func (tn *abstractTreeNode) IsEndpoint() bool        { return false }
func (tn *abstractTreeNode) IsInternet() bool        { return false }
func (tn *abstractTreeNode) IsInternetService() bool { return false }
func (tn *abstractTreeNode) IsUser() bool            { return false }
func (tn *abstractTreeNode) IsVsiConnector() bool    { return false }
func (tn *abstractTreeNode) IsDirectedEdge() bool    { return false }
func (tn *abstractTreeNode) IsUnDirectedEdge() bool  { return false }

func newAbstractTreeNode(parent TreeNodeInterface, name string) abstractTreeNode {
	tn := abstractTreeNode{parent: parent, name: name}
	tn.setID()
	return tn
}
func (tn *abstractTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return nil, nil, nil
}
