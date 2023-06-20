package common

import (
	"fmt"
	"testing"
)

func TestHCbasic(t *testing.T) {
	cube1 := []*CanonicalIntervalSet{CreateFromInterval(1, 100)}
	cube2 := []*CanonicalIntervalSet{CreateFromInterval(1, 100)}
	cube3 := []*CanonicalIntervalSet{CreateFromInterval(1, 200)}
	cube4 := []*CanonicalIntervalSet{CreateFromInterval(1, 100), CreateFromInterval(1, 100)}
	cube5 := []*CanonicalIntervalSet{CreateFromInterval(1, 100), CreateFromInterval(1, 100)}
	cube6 := []*CanonicalIntervalSet{CreateFromInterval(1, 100), CreateFromInterval(1, 200)}

	a := CreateFromCube(cube1)
	b := CreateFromCube(cube2)
	c := CreateFromCube(cube3)
	d := CreateFromCube(cube4)
	e := CreateFromCube(cube5)
	f := CreateFromCube(cube6)

	if !a.Equals(b) {
		t.FailNow()
	}
	if a.Equals(c) {
		t.FailNow()
	}
	if b.Equals(c) {
		t.FailNow()
	}
	//nolint:all
	/*if !c.Equals(c) {
		t.FailNow()
	}
	if !a.Equals(a) {
		t.FailNow()
	}
	if !b.Equals(b) {
		t.FailNow()
	}*/
	if !d.Equals(e) {
		t.FailNow()
	}
	if !e.Equals(d) {
		t.FailNow()
	}
	if d.Equals(f) {
		t.FailNow()
	}
	if f.Equals(d) {
		t.FailNow()
	}
}

func TestCopy(t *testing.T) {
	cube1 := []*CanonicalIntervalSet{CreateFromInterval(1, 100)}
	a := CreateFromCube(cube1)
	b := a.Copy()
	if !a.Equals(b) {
		t.FailNow()
	}
	if !b.Equals(a) {
		t.FailNow()
	}
	if a == b {
		t.FailNow()
	}
}

func TestString(t *testing.T) {
	cube1 := []*CanonicalIntervalSet{CreateFromInterval(1, 100)}
	cube2 := []*CanonicalIntervalSet{CreateFromInterval(1, 100), CreateFromInterval(1, 100)}
	a := CreateFromCube(cube1)
	b := CreateFromCube(cube2)
	fmt.Println(a.String())
	fmt.Println(b.String())
	fmt.Println("done")
}

func TestOr(t *testing.T) {
	cube1 := []*CanonicalIntervalSet{CreateFromInterval(1, 100), CreateFromInterval(1, 100)}
	cube2 := []*CanonicalIntervalSet{CreateFromInterval(1, 90), CreateFromInterval(1, 200)}
	a := CreateFromCube(cube1)
	b := CreateFromCube(cube2)
	c := a.Union(b)
	fmt.Println(a.String())
	fmt.Println(b.String())
	fmt.Println(c.String())
	fmt.Println("done")
}

func addCube1Dim(o *CanonicalHypercubeSet, start, end int64) *CanonicalHypercubeSet {
	cube := []*CanonicalIntervalSet{CreateFromInterval(start, end)}
	a := CreateFromCube(cube)
	return o.Union(a)
}

func addCube2Dim(o *CanonicalHypercubeSet, start1, end1, start2, end2 int64) *CanonicalHypercubeSet {
	cube := []*CanonicalIntervalSet{CreateFromInterval(start1, end1), CreateFromInterval(start2, end2)}
	a := CreateFromCube(cube)
	return o.Union(a)
}

func addCube3Dim(o *CanonicalHypercubeSet, s1, e1, s2, e2, s3, e3 int64) *CanonicalHypercubeSet {
	cube := []*CanonicalIntervalSet{CreateFromInterval(s1, e1), CreateFromInterval(s2, e2), CreateFromInterval(s3, e3)}
	a := CreateFromCube(cube)
	return o.Union(a)
}

func TestBasic(t *testing.T) {
	a := NewCanonicalHypercubeSet(1)
	a = addCube1Dim(a, 1, 2)
	a = addCube1Dim(a, 5, 6)
	a = addCube1Dim(a, 3, 4)
	b := NewCanonicalHypercubeSet(1)
	b = addCube1Dim(b, 1, 6)
	if !a.Equals(b) {
		t.FailNow()
	}
}

func TestBasic2(t *testing.T) {
	a := NewCanonicalHypercubeSet(2)
	a = addCube2Dim(a, 1, 2, 1, 5)
	a = addCube2Dim(a, 1, 2, 7, 9)
	a = addCube2Dim(a, 1, 2, 6, 7)
	b := NewCanonicalHypercubeSet(2)
	b = addCube2Dim(b, 1, 2, 1, 9)
	if !a.Equals(b) {
		t.FailNow()
	}
}

func TestNew(t *testing.T) {
	a := NewCanonicalHypercubeSet(3)
	a = addCube3Dim(a, 10, 20, 10, 20, 1, 65535)
	a = addCube3Dim(a, 1, 65535, 15, 40, 1, 65535)
	a = addCube3Dim(a, 1, 65535, 100, 200, 30, 80)
	expectedStr := "[(1-9,21-65535),(100-200),(30-80)]; [(1-9,21-65535),(15-40),(1-65535)]"
	expectedStr += "; [(10-20),(10-40),(1-65535)]; [(10-20),(100-200),(30-80)]"
	actualStr := a.String()
	if actualStr != expectedStr {
		t.FailNow()
	}
	fmt.Println(a.String())
	fmt.Println("done")
}

func checkContained(t *testing.T, a, b *CanonicalHypercubeSet, expected bool) {
	contained, err := a.ContainedIn(b)
	if contained != expected || err != nil {
		t.FailNow()
	}
}

func checkEquals(t *testing.T, a, b *CanonicalHypercubeSet, expected bool) {
	res := a.Equals(b)
	if res != expected {
		t.FailNow()
	}
}

func TestContainedIn(t *testing.T) {
	a := CreateFromCubeShort(1, 100, 200, 300)
	b := CreateFromCubeShort(10, 80, 210, 280)
	checkContained(t, b, a, true)
	b = addCube2Dim(b, 10, 200, 210, 280)
	checkContained(t, b, a, false)
}

func TestContainedIn2(t *testing.T) {
	c := CreateFromCubeShort(1, 100, 200, 300)
	c = addCube2Dim(c, 150, 180, 20, 300)
	c = addCube2Dim(c, 200, 240, 200, 300)
	c = addCube2Dim(c, 241, 300, 200, 350)

	a := CreateFromCubeShort(1, 100, 200, 300)
	a = addCube2Dim(a, 150, 180, 20, 300)
	a = addCube2Dim(a, 200, 240, 200, 300)
	a = addCube2Dim(a, 242, 300, 200, 350)

	d := CreateFromCubeShort(210, 220, 210, 280)
	e := CreateFromCubeShort(210, 310, 210, 280)
	f := CreateFromCubeShort(210, 250, 210, 280)
	f1 := CreateFromCubeShort(210, 240, 210, 280)
	f2 := CreateFromCubeShort(241, 250, 210, 280)

	checkContained(t, d, c, true)
	checkContained(t, e, c, false)
	checkContained(t, f1, c, true)
	checkContained(t, f2, c, true)
	checkContained(t, f, c, true)
	checkContained(t, f, a, false)
}

func TestContainedIn3(t *testing.T) {
	a := CreateFromCubeShort(105, 105, 54, 54)
	b := CreateFromCubeShort(0, 204, 0, 255)
	b = addCube2Dim(b, 205, 205, 0, 53)
	b = addCube2Dim(b, 205, 205, 55, 255)
	b = addCube2Dim(b, 206, 254, 0, 255)
	checkContained(t, a, b, true)
}

func TestContainedIn4(t *testing.T) {
	a := CreateFromCubeShort(105, 105, 54, 54)
	b := CreateFromCubeShort(200, 204, 0, 255)
	checkContained(t, a, b, false)
}

func TestContainedIn5(t *testing.T) {
	a := CreateFromCubeShort(100, 200, 54, 65, 60, 300)
	b := CreateFromCubeShort(110, 120, 0, 10, 0, 255)
	checkContained(t, b, a, false)
}

func TestEquals(t *testing.T) {
	a := CreateFromCubeShort(1, 2)
	b := CreateFromCubeShort(1, 2)
	checkEquals(t, a, b, true)
	c := CreateFromCubeShort(1, 2, 1, 5)
	d := CreateFromCubeShort(1, 2, 1, 5)
	checkEquals(t, c, d, true)
	c = addCube2Dim(c, 1, 2, 7, 9)
	c = addCube2Dim(c, 1, 2, 6, 7)
	c = addCube2Dim(c, 4, 8, 1, 9)
	res := CreateFromCubeShort(4, 8, 1, 9)
	res = addCube2Dim(res, 1, 2, 1, 9)
	checkEquals(t, res, c, true)

	a = addCube1Dim(a, 5, 6)
	a = addCube1Dim(a, 3, 4)
	res1 := CreateFromCubeShort(1, 6)
	checkEquals(t, res1, a, true)

	d = addCube2Dim(d, 1, 2, 1, 5)
	d = addCube2Dim(d, 5, 6, 1, 5)
	d = addCube2Dim(d, 3, 4, 1, 5)
	res2 := CreateFromCubeShort(1, 6, 1, 5)
	checkEquals(t, res2, d, true)
}

func TestBasicAddCube(t *testing.T) {
	a := CreateFromCubeShort(1, 2)
	a = addCube1Dim(a, 8, 10)
	b := a
	a = addCube1Dim(a, 1, 2)
	a = addCube1Dim(a, 6, 10)
	a = addCube1Dim(a, 1, 10)
	res := CreateFromCubeShort(1, 10)
	checkEquals(t, res, a, true)
	checkEquals(t, res, b, false)
}
func TestBasicAddHole(t *testing.T) {
	a := CreateFromCubeShort(1, 10)
	b := a.Subtraction(CreateFromCubeShort(3, 20))
	c := a.Subtraction(CreateFromCubeShort(0, 20))
	d := a.Subtraction(CreateFromCubeShort(0, 5))
	e := a.Subtraction(CreateFromCubeShort(12, 14))
	a = a.Subtraction(CreateFromCubeShort(3, 7))
	f := CreateFromCubeShort(1, 2)
	f = addCube1Dim(f, 8, 10)
	checkEquals(t, a, f, true)
	checkEquals(t, b, CreateFromCubeShort(1, 2), true)
	checkEquals(t, c, NewCanonicalHypercubeSet(1), true)
	checkEquals(t, d, CreateFromCubeShort(6, 10), true)
	checkEquals(t, e, CreateFromCubeShort(1, 10), true)
}

func TestAddHoleBasic2(t *testing.T) {
	a := CreateFromCubeShort(1, 100, 200, 300)
	b := a.Copy()
	c := a.Copy()
	a = a.Subtraction(CreateFromCubeShort(50, 60, 220, 300))
	resA := CreateFromCubeShort(61, 100, 200, 300)
	resA = addCube2Dim(resA, 50, 60, 200, 219)
	resA = addCube2Dim(resA, 1, 49, 200, 300)
	checkEquals(t, a, resA, true)

	b = b.Subtraction(CreateFromCubeShort(50, 1000, 0, 250))
	resB := CreateFromCubeShort(50, 100, 251, 300)
	resB = addCube2Dim(resB, 1, 49, 200, 300)
	checkEquals(t, b, resB, true)

	c = addCube2Dim(c, 400, 700, 200, 300)
	c = c.Subtraction(CreateFromCubeShort(50, 1000, 0, 250))
	resC := CreateFromCubeShort(50, 100, 251, 300)
	resC = addCube2Dim(resC, 1, 49, 200, 300)
	resC = addCube2Dim(resC, 400, 700, 251, 300)
	checkEquals(t, c, resC, true)
}

func TestAddHole(t *testing.T) {
	c := CreateFromCubeShort(1, 100, 200, 300)
	c = c.Subtraction(CreateFromCubeShort(50, 60, 220, 300))
	d := CreateFromCubeShort(1, 49, 200, 300)
	d = addCube2Dim(d, 50, 60, 200, 219)
	d = addCube2Dim(d, 61, 100, 200, 300)
	checkEquals(t, c, d, true)
}

func TestAddHole2(t *testing.T) {
	c := CreateFromCubeShort(80, 100, 20, 300)
	c = addCube2Dim(c, 250, 400, 20, 300)
	c = c.Subtraction(CreateFromCubeShort(30, 300, 100, 102))
	d := CreateFromCubeShort(80, 100, 20, 99)
	d = addCube2Dim(d, 80, 100, 103, 300)
	d = addCube2Dim(d, 250, 300, 20, 99)
	d = addCube2Dim(d, 250, 300, 103, 300)
	d = addCube2Dim(d, 301, 400, 20, 300)
	checkEquals(t, c, d, true)
}
func TestAddHole3(t *testing.T) {
	c := CreateFromCubeShort(1, 100, 200, 300)
	c = c.Subtraction(CreateFromCubeShort(1, 100, 200, 300))
	checkEquals(t, c, NewCanonicalHypercubeSet(2), true)
}

func TestIntervalsUnion(t *testing.T) {
	c := CreateFromCubeShort(1, 100, 200, 300)
	c = addCube2Dim(c, 101, 200, 200, 300)
	d := CreateFromCubeShort(1, 200, 200, 300)
	checkEquals(t, c, d, true)
	if c.String() != d.String() {
		t.FailNow()
	}
}

func TestIntervalsUnion2(t *testing.T) {
	c := CreateFromCubeShort(1, 100, 200, 300)
	c = addCube2Dim(c, 101, 200, 200, 300)
	c = addCube2Dim(c, 201, 300, 200, 300)
	c = addCube2Dim(c, 301, 400, 200, 300)
	c = addCube2Dim(c, 402, 500, 200, 300)
	c = addCube2Dim(c, 500, 600, 200, 700)
	c = addCube2Dim(c, 601, 700, 200, 700)

	d := c.Copy()
	d = addCube2Dim(d, 702, 800, 200, 700)

	cExpected := CreateFromCubeShort(1, 400, 200, 300)
	cExpected = addCube2Dim(cExpected, 402, 500, 200, 300)
	cExpected = addCube2Dim(cExpected, 500, 700, 200, 700)
	dExpected := cExpected.Copy()
	dExpected = addCube2Dim(dExpected, 702, 800, 200, 700)
	checkEquals(t, c, cExpected, true)
	checkEquals(t, d, dExpected, true)
}

func TestAndSubOr(t *testing.T) {
	a := CreateFromCubeShort(5, 15, 3, 10)
	b := CreateFromCubeShort(8, 30, 7, 20)

	c := a.Intersection(b)
	d := CreateFromCubeShort(8, 15, 7, 10)
	checkEquals(t, c, d, true)

	f := a.Union(b)
	e := CreateFromCubeShort(5, 15, 3, 6)
	e = addCube2Dim(e, 5, 30, 7, 10)
	e = addCube2Dim(e, 8, 30, 11, 20)
	checkEquals(t, e, f, true)

	g := a.Subtraction(b)
	h := CreateFromCubeShort(5, 7, 3, 10)
	h = addCube2Dim(h, 8, 15, 3, 6)
	checkEquals(t, g, h, true)
}

func TestAnd2(t *testing.T) {
	a := CreateFromCubeShort(5, 15, 3, 10)
	b := CreateFromCubeShort(1, 3, 7, 20)
	b = addCube2Dim(b, 20, 23, 7, 20)
	c := a.Intersection(b)
	checkEquals(t, c, NewCanonicalHypercubeSet(2), true)
}

func TestOr2(t *testing.T) {
	a := CreateFromCubeShort(80, 100, 10053, 10053)
	b := CreateFromCubeShort(1, 65535, 10054, 10054)
	a = a.Union(b)
	expected := CreateFromCubeShort(1, 79, 10054, 10054)
	expected = addCube2Dim(expected, 80, 100, 10053, 10054)
	expected = addCube2Dim(expected, 101, 65535, 10054, 10054)
	checkEquals(t, a, expected, true)
}
