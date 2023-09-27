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
	Src() IconTreeNodeInterface
	Dst() IconTreeNodeInterface
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
	src    IconTreeNodeInterface
	dst    IconTreeNodeInterface
	router IconTreeNodeInterface
	points []point
}

func (tn *abstractLineTreeNode) IsLine() bool {
	return true
}

func (tn *abstractLineTreeNode) SrcID() uint                { return tn.src.ID() }
func (tn *abstractLineTreeNode) DstID() uint                { return tn.dst.ID() }
func (tn *abstractLineTreeNode) Src() IconTreeNodeInterface { return tn.src }
func (tn *abstractLineTreeNode) Dst() IconTreeNodeInterface { return tn.dst }

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
	var iconSrc, iconDst IconTreeNodeInterface
	if src.IsSquare() {
		iconSrc = NewGroupPointTreeNode(src.(SquareTreeNodeInterface), directed, true, "")
	} else {
		iconSrc = src.(IconTreeNodeInterface)
	}
	if dst.IsSquare() {
		iconDst = NewGroupPointTreeNode(dst.(SquareTreeNodeInterface), directed, false, "")
	} else {
		iconDst = dst.(IconTreeNodeInterface)
	}
	if iconSrc.IsGroupingPoint() {
		iconSrc.(*GroupPointTreeNode).setColleague(iconDst)
	}
	if iconDst.IsGroupingPoint() {
		iconDst.(*GroupPointTreeNode).setColleague(iconSrc)
	}

	conn := ConnectivityTreeNode{
		abstractLineTreeNode: abstractLineTreeNode{
			abstractTreeNode: newAbstractTreeNode(network, name),
			src:              iconSrc,
			dst:              iconDst},
		directed: directed}
	network.addLineTreeNode(&conn)
	return &conn
}

// // ////////////////////////////////////////////////////////////////////////////////////////
// type GroupingConnection struct {
// 	srcGroupPoint, dstGroupPoint IconTreeNodeInterface
// 	conn                         LineTreeNodeInterface
// }

// func NewGroupedConnection(
// 	network SquareTreeNodeInterface,
// 	src, dst []IconTreeNodeInterface,
// 	directed bool,
// 	name string) *GroupingConnection {
// 	gc := GroupingConnection{}
// 	if len(src) > 1 {
// 		gc.srcGroupPoint = NewGroupPointTreeNode(src[0].Parent().(SquareTreeNodeInterface), src, &gc, directed, false, name)
// 	} else {
// 		gc.srcGroupPoint = src[0]
// 	}
// 	if len(dst) > 1 {
// 		gc.dstGroupPoint = NewGroupPointTreeNode(dst[0].Parent().(SquareTreeNodeInterface), dst, &gc, directed, true, name)
// 	} else {
// 		gc.dstGroupPoint = dst[0]
// 	}
// 	if gc.srcGroupPoint.IsGroupingPoint() {
// 		gc.srcGroupPoint.(*GroupPointTreeNode).setColleague(gc.dstGroupPoint)
// 	}
// 	if gc.dstGroupPoint.IsGroupingPoint() {
// 		gc.dstGroupPoint.(*GroupPointTreeNode).setColleague(gc.srcGroupPoint)
// 	}
// 	gc.conn = NewConnectivityLineTreeNode(network, gc.srcGroupPoint, gc.dstGroupPoint, directed, name)
// 	return &gc
// }

// func (gc *GroupingConnection) SetGwRouter(gw IconTreeNodeInterface, reverse bool) {
// 	gc.conn.SetRouter(gw, reverse)
// 	if gc.srcGroupPoint.IsGroupingPoint() {
// 		gc.srcGroupPoint.(*GroupPointTreeNode).setColleague(gw)
// 	}
// 	if gc.dstGroupPoint.IsGroupingPoint() {
// 		gc.dstGroupPoint.(*GroupPointTreeNode).setColleague(gw)
// 	}

// }
// func (gc *GroupingConnection) SetFipRouter(isDst bool) {
// 	gp := gc.srcGroupPoint
// 	if isDst {
// 		gp = gc.dstGroupPoint
// 	}
// 	if gp.IsGroupingPoint() {
// 		gp2 := gp.(*GroupPointTreeNode)
// 		for i, _ := range gp2.groupiesConns {
// 			gp2.groupiesConns[i].SetRouter(gp2.groupies[i].(IconTreeNodeInterface), isDst)
// 		}
// 	}
// }
