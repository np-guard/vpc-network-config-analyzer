package common

import (
	"fmt"
	"testing"
)

func TestBasicConnectionSet(t *testing.T) {
	c := NewConnectionSet(false)
	fmt.Println(c.String())
	//c.AddConnection(ProtocolICMP, 7, 7)
	fmt.Println(c.String())

	d := NewConnectionSet(true)
	fmt.Println(d.String())
	e := NewConnectionSet(false)
	//e.AddConnection(ProtocolTCP, 1, 65535)
	d = d.Subtract(e)
	fmt.Println(d.String())
	d = d.Union(e)
	fmt.Println(d.String())

	fmt.Println("done")
}
