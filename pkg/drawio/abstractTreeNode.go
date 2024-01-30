package drawio

import "strings"

const (
	minID      = 100
	nextIDStep = 10
	miniIconID = 1
	niFipID    = 2
	textID     = 3
	tagID      = 4
	decoreID   = 5

	idsPrefix = "FXCXVvDxTQtwc45PbP1s"
)

type abstractTreeNode struct {
	id                uint
	x                 int
	y                 int
	name              string
	width             int
	height            int
	parent            TreeNodeInterface
	location          *Location
	doNotShowInDrawio bool
}

func (tn *abstractTreeNode) Label() string { return tn.name }
func labels2Table(labels []string) string {
	labels2 := []string{}
	for _, l := range labels {
		if l != "" {
			labels2 = append(labels2, l)
		}
	}
	return strings.Join(labels2, "&#xa;")
}
func (tn *abstractTreeNode) ID() uint       { return tn.id }
func (tn *abstractTreeNode) TextID() uint   { return tn.id + textID }
func (tn *abstractTreeNode) X() int         { return tn.x }
func (tn *abstractTreeNode) Y() int         { return tn.y }
func (tn *abstractTreeNode) Height() int    { return tn.height }
func (tn *abstractTreeNode) Width() int     { return tn.width }
func (tn *abstractTreeNode) setXY(x, y int) { tn.x, tn.y = x, y }
func (tn *abstractTreeNode) setWH(w, h int) { tn.width, tn.height = w, h }
func (tn *abstractTreeNode) RouterID() uint { return tn.ID() }

func (tn *abstractTreeNode) Location() *Location             { return tn.location }
func (tn *abstractTreeNode) Parent() TreeNodeInterface       { return tn.parent }
func (tn *abstractTreeNode) DrawioParent() TreeNodeInterface { return tn.parent }

func (tn *abstractTreeNode) setLocation(location *Location) { tn.location = location }
func (tn *abstractTreeNode) setParent(p TreeNodeInterface)  { tn.parent = p }
func (tn *abstractTreeNode) NotShownInDrawio() bool         { return tn.doNotShowInDrawio }
func (tn *abstractTreeNode) SetNotShownInDrawio()           { tn.doNotShowInDrawio = true }

var idCounter uint = minID
func createId() uint{
	idCounter += nextIDStep
	return idCounter
} 
func (tn *abstractTreeNode) setID() {
	if tn.id == 0 {
		tn.id = createId()
	}
}

func (tn *abstractTreeNode) IsLine() bool   { return false }
func (tn *abstractTreeNode) IsIcon() bool   { return false }
func (tn *abstractTreeNode) IsSquare() bool { return false }

func newAbstractTreeNode(parent TreeNodeInterface, name string) abstractTreeNode {
	tn := abstractTreeNode{parent: parent, name: name}
	tn.setID()
	return tn
}
func (tn *abstractTreeNode) children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface) {
	return nil, nil, nil
}
