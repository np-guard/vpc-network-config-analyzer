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
type LogicalLineTreeNode struct {
	abstractLineTreeNode
}

func newLogicalLineTreeNode(network SquareTreeNodeInterface, i1, i2 IconTreeNodeInterface) {
	conn := LogicalLineTreeNode{abstractLineTreeNode{abstractTreeNode: newAbstractTreeNode(network, ""), src: i1, dst: i2}}
	network.addLineTreeNode(&conn)
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
	if src.IsSquare() && src.(SquareTreeNodeInterface).IsGroupingSquare(){
		src = NewGroupPointTreeNode(src.(SquareTreeNodeInterface), directed, true, "")
	}
	if dst.IsSquare()  && dst.(SquareTreeNodeInterface).IsGroupingSquare(){
		dst = NewGroupPointTreeNode(dst.(SquareTreeNodeInterface), directed, false, "")
	}
	if src.IsIcon() && src.(IconTreeNodeInterface).IsGroupingPoint() {
		src.(*GroupPointTreeNode).setColleague(dst.(IconTreeNodeInterface))
	}
	if dst.IsIcon() && dst.(IconTreeNodeInterface).IsGroupingPoint() {
		dst.(*GroupPointTreeNode).setColleague(src.(IconTreeNodeInterface))
	}

	conn := ConnectivityTreeNode{
		abstractLineTreeNode: abstractLineTreeNode{
			abstractTreeNode: newAbstractTreeNode(network, name),
			src:              src,
			dst:              dst},
		directed: directed}
	network.addLineTreeNode(&conn)
	return &conn
}
