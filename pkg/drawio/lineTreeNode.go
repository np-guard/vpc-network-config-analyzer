package drawio

// /////////////////////////////////////////////////////////////////////
//
// ////////////////////////////////////////////////////////////////
type point struct {
	X int
	Y int
}

// //////////////////////////////////////////////////////////////////////////////
type LineTreeNodeInterface interface {
	TreeNodeInterface
	Src() TreeNodeInterface
	Dst() TreeNodeInterface
	SrcID() uint
	DstID() uint
	Points() []point
	setPoints([]point)
	addPoint(x int, y int)
	SetRouter(router IconTreeNodeInterface, reverse bool)
	Router() IconTreeNodeInterface
}

type abstractLineTreeNode struct {
	abstractTreeNode
	src    TreeNodeInterface
	dst    TreeNodeInterface
	router IconTreeNodeInterface
	points []point
}

func (tn *abstractLineTreeNode) IsLine() bool {
	return true
}

func (tn *abstractLineTreeNode) SrcID() uint                { return tn.src.ID() }
func (tn *abstractLineTreeNode) DstID() uint                { return tn.dst.ID() }
func (tn *abstractLineTreeNode) Src() TreeNodeInterface { return tn.src }
func (tn *abstractLineTreeNode) Dst() TreeNodeInterface { return tn.dst }

func (tn *abstractLineTreeNode) DrawioParent() TreeNodeInterface {
	if tn.router != nil {
		return tn.router
	}
	return tn.Parent()
}

func (tn *abstractLineTreeNode) Points() []point               { return tn.points }
func (tn *abstractLineTreeNode) setPoints(points []point)      { tn.points = points }
func (tn *abstractLineTreeNode) Router() IconTreeNodeInterface { return tn.router }

func (tn *abstractLineTreeNode) SetRouter(router IconTreeNodeInterface, reverse bool) {
	tn.router = router
	routeOffset := router.allocateNewRouteOffset()
	if !reverse {
		tn.addPoint(iconSize, iconSize/2+routeOffset)
		tn.addPoint(0, iconSize/2+routeOffset)
	} else {
		tn.addPoint(0, iconSize/2+routeOffset)
		tn.addPoint(iconSize, iconSize/2+routeOffset)
	}
}

func (tn *abstractLineTreeNode) addPoint(x, y int) {
	tn.points = append(tn.points, point{x, y})
}

// ////////////////////////////////////////////////////////////////
type VsiLineTreeNode struct {
	abstractLineTreeNode
}

func newVsiLineTreeNode(network SquareTreeNodeInterface, vsi, ni IconTreeNodeInterface) *VsiLineTreeNode {
	conn := VsiLineTreeNode{abstractLineTreeNode{abstractTreeNode: newAbstractTreeNode(network, ""), src: vsi, dst: ni}}
	network.addLineTreeNode(&conn)
	return &conn
}

// ////////////////////////////////////////////////////////////////
type ConnectivityTreeNode struct {
	abstractLineTreeNode
	directed bool
}

func NewConnectivityLineTreeNode(network SquareTreeNodeInterface,
	src, dst TreeNodeInterface,
	directed bool,
	name string) *ConnectivityTreeNode {
	conn := ConnectivityTreeNode{
		abstractLineTreeNode: abstractLineTreeNode{abstractTreeNode: newAbstractTreeNode(network, name), src: src, dst: dst},
		directed:             directed}
	network.addLineTreeNode(&conn)
	return &conn
}
