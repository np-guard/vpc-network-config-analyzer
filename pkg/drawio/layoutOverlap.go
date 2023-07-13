package drawio

import (
	"math"
)

var NOPOINT = point{-1, -1}
const NpotentiaBP =6

type overlapCell struct {
	hasBP bool
	icon  IconTreeNodeInterface
}

type layoutOverlap struct {
	overlapMatrix [][]overlapCell
	network       TreeNodeInterface
}

func newLayoutOverlap(network TreeNodeInterface) *layoutOverlap {
	lyO := &layoutOverlap{network: network}
	yDim := network.Height() / minSize
	xDim := network.Width() / minSize
	lyO.overlapMatrix = make([][]overlapCell, yDim)
	for i := range lyO.overlapMatrix {
		lyO.overlapMatrix[i] = make([]overlapCell, xDim)
	}
	return lyO
}
func (lyO *layoutOverlap) cell(x, y int) *overlapCell {
	return &(lyO.overlapMatrix[y/minSize][x/minSize])
}

func (lyO *layoutOverlap) fixOverlapping() {
	lyO.setIconsMap()
	lyO.handleLinesOverLines()
	lyO.handleLinesOverIcons()
}

func (lyO *layoutOverlap) setIconsMap() {
	for _, tn := range getAllNodes(lyO.network) {
		if tn.IsIcon() {
			x, y := absoluteGeometry(tn)
			for ox := x; ox < x+iconSize; ox += minSize {
				for oy := y; oy < y+iconSize; oy += minSize {
					lyO.cell(ox, oy).icon = tn.(IconTreeNodeInterface)
				}
			}
		}
	}
}

func (lyO *layoutOverlap) handleLinesOverLines() {
	nodes := getAllNodes(lyO.network)
	for i1 := range nodes {
		for i2 := i1 + 1; i2 < len(nodes); i2++ {
			if nodes[i1].IsLine() && nodes[i2].IsLine() {
				line1 := nodes[i1].(LineTreeNodeInterface)
				line2 := nodes[i2].(LineTreeNodeInterface)
				if line1.Src() == line2.Dst() && line1.Dst() == line2.Src() {
					if len(line1.Points()) == 0 && len(line2.Points()) == 0 {
						srcPoint := iconCenterPoint(line1.Src())
						dstPoint := iconCenterPoint(line1.Dst())
						middlePoint := point{(srcPoint.X + dstPoint.X) / 2, (srcPoint.Y + dstPoint.Y) / 2}
						BP := lyO.getBypassPoint(srcPoint, dstPoint, middlePoint, line1)
						if BP != NOPOINT {
							line1.setPoints([]point{getRelativePoint(line1, BP)})
						}
					}
				}
			}
		}
	}
}

func (lyO *layoutOverlap) handleLinesOverIcons() {
	for _, tn := range getAllNodes(lyO.network) {
		if !tn.IsLine() {
			continue
		}
		line := tn.(LineTreeNodeInterface)
		newLinePoint := []point{}
		oldLinePoints := line.Points()
		absPoints := getLineAbsolutePoints(line)
		for pointIndex := range absPoints[0 : len(absPoints)-1] {
			srcP := absPoints[pointIndex]
			desP := absPoints[pointIndex+1]
			for {
				icon := lyO.getOverlappedIcon(srcP, desP, line)
				if icon == nil {
					break
				}
				BP := lyO.getBypassPoint(srcP, desP, iconCenterPoint(icon), line)
				if BP == NOPOINT {
					break
				}
				newLinePoint = append(newLinePoint, getRelativePoint(line, BP))
				srcP = BP
			}
			if pointIndex < len(oldLinePoints) {
				newLinePoint = append(newLinePoint, oldLinePoints[pointIndex])
			}
		}
		line.setPoints(newLinePoint)
	}
}

func (lyO *layoutOverlap) potentialBypassPoints(srcPoint, dstPoint, middlePoint point) []point {
	deltaX, deltaY := (srcPoint.X - dstPoint.X), (srcPoint.Y - dstPoint.Y)
	disXY := int(math.Sqrt(float64(deltaX)*float64(deltaX) + float64(deltaY)*float64(deltaY)))
	BPs := []point{}
	for i := 0; i< NpotentiaBP; i++ {
		verticalVectorSize := pow(-1,i)*(1 + i/2)  * iconSize
		verticalVectorX := verticalVectorSize * deltaY / disXY
		verticalVectorY := verticalVectorSize * deltaX / disXY
		BP := point{max(0, middlePoint.X+verticalVectorX), max(0, middlePoint.Y-verticalVectorY)}
		if lyO.cell(BP.X, BP.Y).icon != nil {
			continue
		}
		for lyO.cell(BP.X, BP.Y).hasBP {
			BP = point{BP.X + minSize, BP.Y + minSize}
		}
		BPs = append(BPs, BP)
	}
	return BPs
}

func (lyO *layoutOverlap) getBypassPoint(srcPoint, dstPoint, middlePoint point, line LineTreeNodeInterface) point {
	BPs := lyO.potentialBypassPoints(srcPoint, dstPoint, middlePoint)
	for _, BP := range BPs {
		if lyO.getOverlappedIcon(srcPoint, BP, line) == nil && lyO.getOverlappedIcon(BP, dstPoint, line) == nil {
			lyO.cell(BP.X, BP.Y).hasBP = true
			return BP
		}
	}
	for _, BP := range BPs {
		if lyO.getOverlappedIcon(srcPoint, BP, line) == nil {
			lyO.cell(BP.X, BP.Y).hasBP = true
			return BP
		}
	}
	for _, BP := range BPs {
		if lyO.getOverlappedIcon(BP, dstPoint, line) == nil {
			lyO.cell(BP.X, BP.Y).hasBP = true
			return BP
		}
	}
	return NOPOINT
}

func (lyO *layoutOverlap) getOverlappedIcon(p1, p2 point, line LineTreeNodeInterface) IconTreeNodeInterface {
	x1, y1 := p1.X, p1.Y
	x2, y2 := p2.X, p2.Y
	nSteps := (abs(x2-x1) + abs(y2-y1)) / (minSize)
	for s := 0; s <= nSteps; s++ {
		x := x1 + (x2-x1)*s/nSteps
		y := y1 + (y2-y1)*s/nSteps
		icon := lyO.cell(x, y).icon
		if icon != nil && icon != line.Src() && icon != line.Dst() && icon != line.Router() {
			return icon
		}
	}
	return nil
}

func getLineAbsolutePoints(line LineTreeNodeInterface) []point {
	absPoints := []point{}
	absPoints = append(absPoints, iconCenterPoint(line.Src()))
	for _, p := range line.Points() {
		absPoints = append(absPoints, getAbsolutePoint(line, p))
	}
	absPoints = append(absPoints, iconCenterPoint(line.Dst()))
	return absPoints
}

func iconCenterPoint(icon IconTreeNodeInterface) point {
	ix, iy := absoluteGeometry(icon)
	return point{ix + iconSize/2, iy + iconSize/2}
}
func getAbsolutePoint(line LineTreeNodeInterface, p point) point {
	if line.Router() != nil {
		x, y := line.Router().absoluteRouterGeometry()
		return point{x + p.X, y + p.Y}
	}
	return p
}

func getRelativePoint(line LineTreeNodeInterface, absPoint point) point {
	px, py := absoluteGeometry(line.DrawioParent())
	if line.Router() != nil {
		px, py = line.Router().absoluteRouterGeometry()
	}
	x := absPoint.X - px
	y := absPoint.Y - py
	return point{x, y}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func abs(a int) int {
	if a > 0 {
		return a
	}
	return -a
}
func pow(a, b int) int {
	if b ==0  {
		return 1
	}
	return pow (a, b-1)*a
}
