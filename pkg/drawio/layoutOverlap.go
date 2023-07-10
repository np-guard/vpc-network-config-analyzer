package drawio

import "math"

type overlapCell struct {
	lines      map[LineTreeNodeInterface]int
	icon       IconTreeNodeInterface
	pointAdded int
}

func (o *overlapCell) hasLine() bool { return len(o.lines) > 0 }
func (o *overlapCell) hasIcon() bool { return o.icon != nil }
func (o *overlapCell) addLine(l LineTreeNodeInterface, pointIndex int) {
	if o.icon != l.Src() && o.icon != l.Dst() {
		o.lines[l] = pointIndex
	}
}
func (o *overlapCell) hasOverlap() bool {
	if o.icon == nil {
		return false
	}
	for l := range o.lines {
		if o.icon != l.Src() && o.icon != l.Dst() && o.icon != l.Router() {
			return true
		}
	}
	return false
}

type layoutOverlap struct {
	overlapMap [5000][5000]overlapCell
}

func newLayoutOverlap() *layoutOverlap {
	lyO := &layoutOverlap{}
	for y := 0; y < 5000; y++ {
		for x := 0; x < 5000; x++ {
			lyO.overlapMap[y][x].lines = map[LineTreeNodeInterface]int{}
		}
	}
	return lyO
}

func (lyO *layoutOverlap) fixOverlapping(network TreeNodeInterface) {
	lyO.createOverlappingMap(network)
	lyO.createBypasses()
}

func getBypassPoint2(icons []IconTreeNodeInterface, p1 point, p2 point) (int, int) {
	ix, iy := absoluteGeometry(icons[0])
	x, y := (p1.X+p2.X+ix)/3+iconSize*2, (p1.Y+p2.Y+iy)/3+iconSize*2
	return x, y
}

func getBypassPoint(icons []IconTreeNodeInterface, p1 point, p2 point) (int, int) {
	dx, dy := (p1.X - p2.X), (p1.Y - p2.Y)
	dis := int(math.Sqrt(float64(dx)*float64(dx) + float64(dy)*float64(dy)))
	ix, iy := absoluteGeometry(icons[0])
	ix, iy = ix+iconSize/2, iy+iconSize/2
	return ix + iconSize*dy/dis, iy - iconSize*dx/dis
	//	return ix, iy
}

func (lyO *layoutOverlap) createBypasses() {
	lineOverlaps := map[LineTreeNodeInterface]map[int][]IconTreeNodeInterface{}

	for y := 0; y < 5000; y++ {
		for x := 0; x < 5000; x++ {
			olc := &lyO.overlapMap[y][x]
			for l, pointIndex := range olc.lines {
				if olc.icon != nil && olc.icon != l.Src() && olc.icon != l.Dst() && olc.icon != l.Router() {
					if lineOverlaps[l] == nil {
						lineOverlaps[l] = map[int][]IconTreeNodeInterface{}
					}
					lineOverlaps[l][pointIndex] = append(lineOverlaps[l][pointIndex], olc.icon)
				}
			}
		}
	}
	for l := range lineOverlaps {
		newLinePoint := []point{}
		oldLinePoints := l.Points()
		oldPointIndex := 0
		absPoints := getAbsolutePoints(l)
		for pointIndex := 0; pointIndex < 30; pointIndex++ {
			if icons := lineOverlaps[l][pointIndex]; icons != nil {
				for ; oldPointIndex < pointIndex; oldPointIndex++ {
					newLinePoint = append(newLinePoint, oldLinePoints[oldPointIndex])
				}
				p1, p2 := absPoints[pointIndex], absPoints[pointIndex+1]
				x, y := getBypassPoint(icons, p1, p2)
				lyO.overlapMap[y/minSize][x/minSize].pointAdded += 1
				px, py := absoluteGeometry(l.Parent())
				if l.Router() != nil {
					px, py = l.Router().absoluteRouterGeometry()
				}
				x -= px
				y -= py

				newLinePoint = append(newLinePoint, point{x, y})
			}
		}
		for ; oldPointIndex < len(oldLinePoints); oldPointIndex++ {
			newLinePoint = append(newLinePoint, oldLinePoints[oldPointIndex])
		}
		l.setPoints(newLinePoint)
	}
}

func getAbsolutePoints(line LineTreeNodeInterface) []point {
	absPoints := []point{}
	x, y := absoluteGeometry(line.Src())
	absPoints = append(absPoints, point{x + iconSize/2, y + iconSize/2})
	for _, p := range line.Points() {
		if line.Router() != nil {
			x, y := line.Router().absoluteRouterGeometry()
			absPoints = append(absPoints, point{x + p.X, y + p.Y})

		} else {
			absPoints = append(absPoints, point{p.X, p.Y})
		}
	}
	x, y = absoluteGeometry(line.Dst())
	absPoints = append(absPoints, point{x + iconSize/2, y + iconSize/2})
	return absPoints

}
func (lyO *layoutOverlap) createOverlappingMap(network TreeNodeInterface) {
	for _, tn := range getAllNodes(network) {
		if tn.IsIcon() {
			x, y := absoluteGeometry(tn)
			for ox := x; ox < x+iconSize; ox += minSize {
				for oy := y; oy < y+iconSize; oy += minSize {
					lyO.overlapMap[oy/minSize][ox/minSize].icon = tn.(IconTreeNodeInterface)
				}
			}
		}
	}
	for _, tn := range getAllNodes(network) {
		if tn.IsLine() {
			line := tn.(LineTreeNodeInterface)
			absPoints := getAbsolutePoints(line)
			for pointIndex := range absPoints {
				if pointIndex == len(absPoints)-1 {
					continue
				}
				x1 := absPoints[pointIndex].X
				y1 := absPoints[pointIndex].Y
				x2 := absPoints[pointIndex+1].X
				y2 := absPoints[pointIndex+1].Y
				nsteps := int(math.Abs(float64(x2-x1)) + math.Abs(float64(y2-y1))/float64(minSize))

				for s := 0; s <= nsteps; s++ {
					x := x1 + (x2-x1)*s/nsteps
					y := y1 + (y2-y1)*s/nsteps
					lyO.overlapMap[y/minSize][x/minSize].addLine(tn.(LineTreeNodeInterface), pointIndex)
				}
			}
		}
	}
}
