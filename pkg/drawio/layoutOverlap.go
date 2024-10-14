/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package drawio

import (
	"math"
)

// layoutOverlap is a struct that handle overlapping between lines, and overlapping lines on icons.
// We have two kind of overlapping:
//    1. Lines overlapping - two lines are at the same path (lines that has the same set of (src,dst) )
//    2. Lines that overlap icons
// The way to handle the overlap is to add points to the lines (aka bypass points).
// The detection overlapping is done by holding a 2D matrix, that represents the drawio picture.
// a cell in the matrix represent square of overlapMinSize*overlapMinSize in the picture.
// The cell hold the information whether:
//    1. there is an icon in the square.
//    2. there is a bypass point in the square
// Handling overlapping is done in three steps:
//    1. update the matrix with the icons locations
//    2. handling pairs of lines sharing the same path -
//       this is done by adding a bypass point to one of the lines, at the middle of the line
//    3. handling lines overlapping  icons - this is done by adding a bypass points to the line, next to the icons
// in both steps 2,3. choosing the bypass point is done in two steps:
//    1. calculate a list of potential bypass points, around the icon, (or around the middle of the line)
//    2. choose the best point, and add it to the line.

var noPoint = point{-1, -1}

const nPotentialBP = 6
const widthBetweenLines = 3
const overlapMinSize = minSize / 2

type overlapCell struct {
	hasBypassPoint bool
	icon           IconTreeNodeInterface
}

type layoutOverlap struct {
	overlapMatrix [][]overlapCell
	network       TreeNodeInterface
}

func newLayoutOverlap(network TreeNodeInterface) *layoutOverlap {
	lyO := &layoutOverlap{network: network}
	yDim := network.Height() / overlapMinSize
	xDim := network.Width() / overlapMinSize
	lyO.overlapMatrix = make([][]overlapCell, yDim)
	for i := range lyO.overlapMatrix {
		lyO.overlapMatrix[i] = make([]overlapCell, xDim)
	}
	return lyO
}

func (lyO *layoutOverlap) cell(x, y int) *overlapCell {
	if x < 0 || y < 0 || y/overlapMinSize >= len(lyO.overlapMatrix) || x/overlapMinSize >= len(lyO.overlapMatrix[0]) {
		return nil
	}
	return &(lyO.overlapMatrix[y/overlapMinSize][x/overlapMinSize])
}

// fixOverlapping() is the entry method.
func (lyO *layoutOverlap) fixOverlapping() {
	// The steps of handling overlapping:
	lyO.handleGroupingLinesOverBorders()
	lyO.setIconsMap()
	lyO.handleLinesOverLines()
	lyO.handleLinesOverIcons()
}

// setIconsMap() update the cells of the matrix with icons positions:
func (lyO *layoutOverlap) setIconsMap() {
	for _, tn := range getAllIcons(lyO.network) {
		x, y := absoluteGeometry(tn)
		for ox := x; ox <= x+tn.IconSize(); ox += overlapMinSize {
			for oy := y; oy <= y+tn.IconSize(); oy += overlapMinSize {
				lyO.cell(ox, oy).icon = tn
			}
		}
	}
}

// handleGroupingLinesOverBorders() add points to the connectivity line in cases the line is on the square border
// (relevant for lines between two grouping point which share the same column)
func (lyO *layoutOverlap) handleGroupingLinesOverBorders() {
	// we count how many lines are already on the column, so they wont overlap each other:
	linesOnCol := map[*col]int{}
	for _, line := range getAllLines(lyO.network) {
		if !line.Src().(IconTreeNodeInterface).IsGroupingPoint() || !line.Dst().(IconTreeNodeInterface).IsGroupingPoint() {
			continue
		}
		src, dst := line.Src().(*GroupPointTreeNode), line.Dst().(*GroupPointTreeNode)
		if src.Location().firstCol != dst.Location().firstCol {
			continue
		}
		if len(line.Points()) != 0 {
			continue
		}
		col := src.Location().firstCol
		lineX := col.x() + col.thickness/2 - linesOnCol[col]*widthBetweenLines
		for _, gi := range []*GroupPointTreeNode{src, dst} {
			if gi.hasShownSquare() {
				// adding a point:
				p := centerPoint(gi)
				line.addPoint(lineX, p.Y)
			} else {
				// the point is already on the middle of the column, just moving the point according to the number of previous lines:
				x, y := gi.X()-linesOnCol[col]*widthBetweenLines, gi.Y()
				gi.setXY(x, y)
			}
		}
		linesOnCol[col] += 1
	}
}

// handleLinesOverLines() - find pairs of overlapping lines, and add point to one of them
func (lyO *layoutOverlap) handleLinesOverLines() {
	lines := getAllLines(lyO.network)
	for i1 := range lines {
		for i2 := i1 + 1; i2 < len(lines); i2++ {
			line1 := lines[i1]
			line2 := lines[i2]
			if line1.Src() != line2.Dst() || line1.Dst() != line2.Src() {
				continue
			}
			if len(line1.Points()) != 0 || len(line2.Points()) != 0 {
				continue
			}
			srcPoint := centerPoint(line1.Src())
			dstPoint := centerPoint(line1.Dst())
			middlePoint := point{(srcPoint.X + dstPoint.X) / 2, (srcPoint.Y + dstPoint.Y) / 2}
			BP := lyO.getBypassPoint(srcPoint, dstPoint, middlePoint, line1)
			if BP != noPoint {
				line1.setPoints([]point{getRelativePoint(line1, BP)})
			}
		}
	}
}

// handleLinesOverIcons() - handle lines that overlap icons:
//  1. we basically create a new list of points, a mix of the line old points, and the new bypass points.
//  2. each line is being split to intervals - the intervals are basically a list of the points of the line,
//     plus the src and the dst of the line.
//     an interval is the basically a two sequential points.
//  3. for each interval, if there is an icon that is overlapped by the interval, than we add a bypass point between those points.
//  4. the new bypass point might create new overlapping, in that case, we will add a new bypass point, and so on...
func (lyO *layoutOverlap) handleLinesOverIcons() {
	for _, line := range getAllLines(lyO.network) {
		newLinePoint := []point{}
		oldLinePoints := line.Points()
		absPoints := getLineAbsolutePoints(line)
		for pointIndex := range absPoints[0 : len(absPoints)-1] {
			srcP := absPoints[pointIndex]
			desP := absPoints[pointIndex+1]
			// add bypass points until there is no overlap with icons (or until no bypass can be found)
			for {
				icon := lyO.getOverlappedIcon(srcP, desP, line)
				if icon == nil {
					// there is no overlap
					break
				}
				BP := lyO.getBypassPoint(srcP, desP, centerPoint(icon), line)
				if BP == noPoint {
					// we could not find a suitable bypass point
					break
				}
				// adding the new bypass point
				newLinePoint = append(newLinePoint, getRelativePoint(line, BP))
				// making the BP point to be the src, and repeat the loop, looking for new overlapping
				srcP = BP
			}
			// unless is the last point ( last point is line destination) we also add the old point to the new point list
			if pointIndex < len(oldLinePoints) {
				newLinePoint = append(newLinePoint, oldLinePoints[pointIndex])
			}
		}
		line.setPoints(newLinePoint)
	}
}

// potentialBypassPoints() calculate a list of potential bypass points.
// for the interval srcPoint<->dstPoint.
// we collect the points from the line that cross the interval in the middlePoint, at 90 deg.
// The distances of the potential bypass points from the middlePoint are iconSize, -iconSize, 2*iconSize ...
func (lyO *layoutOverlap) potentialBypassPoints(srcPoint, dstPoint, middlePoint point) []point {
	deltaX, deltaY := (srcPoint.X - dstPoint.X), (srcPoint.Y - dstPoint.Y)
	disXY := int(math.Sqrt(float64(deltaX)*float64(deltaX) + float64(deltaY)*float64(deltaY)))
	BPs := []point{}
	if disXY <= 2*minSize {
		// the points are too close, there is no point to bypass.
		return BPs
	}
	for i := 0; i < nPotentialBP; i++ {
		verticalVectorSize := pow(-1, i) * (1 + i/2) * iconSize
		verticalVectorX := verticalVectorSize * deltaY / disXY
		verticalVectorY := verticalVectorSize * deltaX / disXY
		BP := point{max(0, middlePoint.X+verticalVectorX), max(0, middlePoint.Y-verticalVectorY)}
		if lyO.cell(BP.X, BP.Y) == nil || lyO.cell(BP.X, BP.Y).icon != nil {
			continue
		}
		// in case we already have a a bypassPoint in the cell, we will try to search a free cell around it:
		// todo: look for a free cell not so close to the point
		for lyO.cell(BP.X, BP.Y) != nil {
			if !lyO.cell(BP.X, BP.Y).hasBypassPoint {
				BPs = append(BPs, BP)
				break
			}
			BP = point{BP.X + overlapMinSize, BP.Y + overlapMinSize}
		}
	}
	return BPs
}

// getBypassPoint() select the best BS, the closest that creates minimum new overlapping
func (lyO *layoutOverlap) getBypassPoint(srcPoint, dstPoint, middlePoint point, line LineTreeNodeInterface) point {
	BPs := lyO.potentialBypassPoints(srcPoint, dstPoint, middlePoint)
	for _, BP := range BPs {
		if lyO.getOverlappedIcon(srcPoint, BP, line) == nil && lyO.getOverlappedIcon(BP, dstPoint, line) == nil {
			lyO.cell(BP.X, BP.Y).hasBypassPoint = true
			return BP
		}
	}
	for _, BP := range BPs {
		if lyO.getOverlappedIcon(srcPoint, BP, line) == nil {
			lyO.cell(BP.X, BP.Y).hasBypassPoint = true
			return BP
		}
	}
	for _, BP := range BPs {
		if lyO.getOverlappedIcon(BP, dstPoint, line) == nil {
			lyO.cell(BP.X, BP.Y).hasBypassPoint = true
			return BP
		}
	}
	return noPoint
}

// getOverlappedIcon() checks if there is an icon overlap on the interval
func (lyO *layoutOverlap) getOverlappedIcon(p1, p2 point, line LineTreeNodeInterface) IconTreeNodeInterface {
	x1, y1 := p1.X, p1.Y
	x2, y2 := p2.X, p2.Y
	nSteps := max(1, max(abs(x2-x1), abs(y2-y1))/(overlapMinSize))
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

// some methods to convert absolute point to relative, and vis versa:
func getLineAbsolutePoints(line LineTreeNodeInterface) []point {
	absPoints := []point{centerPoint(line.Src())}
	for _, p := range line.Points() {
		absPoints = append(absPoints, getAbsolutePoint(line, p))
	}
	absPoints = append(absPoints, centerPoint(line.Dst()))
	return absPoints
}

func centerPoint(tn TreeNodeInterface) point {
	ix, iy := absoluteGeometry(tn)
	return point{ix + tn.Width()/2, iy + tn.Height()/2}
}

func getAbsolutePoint(line LineTreeNodeInterface, p point) point {
	if line.Router() != nil {
		x, y := line.Router().absoluteRouterGeometry()
		return point{x + p.X, y + p.Y}
	}
	lpx, lpy := absoluteGeometry(line.Parent())
	return point{lpx + p.X, lpy + p.Y}
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

// the most common line in stackoverflow:
// "There is no built-in function for  <....> in golang, but it’s simple to write your own"
func abs(a int) int {
	if a > 0 {
		return a
	}
	return -a
}

func pow(a, b int) int {
	return int(math.Pow(float64(a), float64(b)))
}
