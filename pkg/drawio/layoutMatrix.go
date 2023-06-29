package drawio

const (
	minMatrixSize = 30
)

type layer struct {
	thickness int
	distance  int
	matrix    *layoutMatrix
	index     int
}

type row layer

func newRow(matrix *layoutMatrix, index int) *row { return &row{matrix: matrix, index: index} }
func (r *row) setHeight(height int)               { r.thickness = height }
func (r *row) setY(y int)                         { r.distance = y }
func (r *row) height() int                        { return r.thickness }
func (r *row) y() int                             { return r.distance }

type col layer

func newCol(matrix *layoutMatrix, index int) *col { return &col{matrix: matrix, index: index} }
func (c *col) setWidth(width int)                 { c.thickness = width }
func (c *col) setX(y int)                         { c.distance = y }
func (c *col) width() int                         { return c.thickness }
func (c *col) x() int                             { return c.distance }

/////////////////////////////////////////////////////////////////////////////////

type Location struct {
	firstRow *row
	lastRow  *row
	firstCol *col
	lastCol  *col
	xOffset  int
	yOffset  int
}

func newLocation(firstRow, lastRow *row, firstCol, lastCol *col) *Location {
	return &Location{firstRow, lastRow, firstCol, lastCol, 0, 0}
}
func newCellLocation(firstRow *row, firstCol *col) *Location {
	return newLocation(firstRow, firstRow, firstCol, firstCol)
}
func (l *Location) nextRow() *row {
	return l.lastRow.matrix.rows[l.lastRow.index+1]
}
func (l *Location) nextCol() *col {
	return l.lastCol.matrix.cols[l.lastCol.index+1]
}
func (l *Location) prevRow() *row {
	return l.firstRow.matrix.rows[l.firstRow.index-1]
}
func (l *Location) prevCol() *col {
	return l.firstCol.matrix.cols[l.firstCol.index-1]
}

// copy() is not a deep copy, we only copy the pointers
func (l *Location) copy() *Location {
	return &Location{
		firstRow: l.firstRow,
		lastRow:  l.lastRow,
		firstCol: l.firstCol,
		lastCol:  l.lastCol,
		xOffset:  l.xOffset,
		yOffset:  l.yOffset,
	}
}

func mergeLocations(locations []*Location) *Location {
	var firstRow, lastRow *row = nil, nil
	var firstCol, lastCol *col = nil, nil
	for _, l := range locations {
		if l == nil {
			continue
		}
		if firstRow == nil || l.firstRow.index < firstRow.index {
			firstRow = l.firstRow
		}
		if lastRow == nil || l.lastRow.index > lastRow.index {
			lastRow = l.lastRow
		}
		if lastCol == nil || l.firstCol.index < firstCol.index {
			firstCol = l.firstCol
		}
		if lastCol == nil || l.lastCol.index > lastCol.index {
			lastCol = l.lastCol
		}
	}
	return newLocation(firstRow, lastRow, firstCol, lastCol)
}

////////////////////////////////////////////////////

type layoutMatrix struct {
	rows []*row
	cols []*col
}

func newLayoutMatrix() *layoutMatrix {
	matrix := layoutMatrix{}
	matrix.expend(minMatrixSize, minMatrixSize)
	return &matrix
}
func (matrix *layoutMatrix) allocateCellLocation(rowIndex, colIndex int) *Location {
	for rowIndex >= len(matrix.rows) {
		matrix.expend(len(matrix.rows)+minMatrixSize, len(matrix.cols))
	}
	for colIndex >= len(matrix.cols) {
		matrix.expend(len(matrix.rows), len(matrix.cols)+minMatrixSize)
	}
	return newCellLocation(matrix.rows[rowIndex], matrix.cols[colIndex])
}
func (matrix *layoutMatrix) removeUnusedLayers() {
	newRows := []*row{}
	newCols := []*col{}
	for _, row := range matrix.rows {
		if row.height() > 0 {
			row.index = len(newRows)
			newRows = append(newRows, row)
		}
	}
	for _, col := range matrix.cols {
		if col.width() > 0 {
			col.index = len(newCols)
			newCols = append(newCols, col)
		}
	}
	matrix.rows = newRows
	matrix.cols = newCols
}

func (matrix *layoutMatrix) expend(nRows, nCols int) {
	matrix.convert(nRows, nCols, func(i int) int { return i })
}

func (matrix *layoutMatrix) resize(newIndex func(int) int) {
	matrix.convert(newIndex(len(matrix.rows)), newIndex(len(matrix.cols)), newIndex)
}

func (matrix *layoutMatrix) convert(nRows, nCols int, newIndex func(int) int) {
	newRows := make([]*row, nRows)
	newCols := make([]*col, nCols)
	for i := range newRows {
		newRows[i] = newRow(matrix, i)
	}
	for i := range newCols {
		newCols[i] = newCol(matrix, i)
	}
	for i, row := range matrix.rows {
		newRows[newIndex(i)] = row
		row.index = newIndex(i)
	}
	for i, col := range matrix.cols {
		newCols[newIndex(i)] = col
		col.index = newIndex(i)
	}
	matrix.rows = newRows
	matrix.cols = newCols
}

func (matrix *layoutMatrix) setLayersDistance() {
	y := 0
	for _, row := range matrix.rows {
		row.setY(y)
		y += row.height()
	}
	x := 0
	for _, col := range matrix.cols {
		col.setX(x)
		x += col.width()
	}
}
