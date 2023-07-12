package common

import (
	"fmt"
	"testing"
)

// TODO: Add test assertions
func TestBasicConnectionSet(t *testing.T) {
	c := NewConnectionSet(false)
	fmt.Println(c.String())
	c.AddICMPConnection(7, 7, 5, 5)
	fmt.Println(c.String())

	d := NewConnectionSet(true)
	fmt.Println(d.String())
	e := NewConnectionSet(false)
	e.AddTCPorUDPConn(ProtocolTCP, 1, 65535, 1, 65535)
	d = d.Subtract(e)
	fmt.Println(d.String())
	d = d.Union(e)
	fmt.Println(d.String())

	h := NewConnectionSet(false)
	h.AddTCPorUDPConn(ProtocolTCP, 1, 65535, 1, 65535)
	h.AddTCPorUDPConn(ProtocolUDP, 1, 65535, 1, 65535)
	fmt.Printf("%s", h.String())

	fmt.Println("done")
}

func TestBasicConnectionSet2(t *testing.T) {
	c := NewConnectionSet(false)
	c.AddICMPConnection(7, 7, 5, 5)
	d := NewConnectionSet(true)
	e := NewConnectionSet(false)
	e.AddTCPorUDPConn(ProtocolTCP, 1, 65535, 1, 65535)
	d = d.Subtract(e)
	d = d.Subtract(c)
	fmt.Println(d.String())

	fmt.Println("done")
}

func TestBasicConnectionSet3(t *testing.T) {
	c := NewConnectionSet(false)
	c.AddICMPConnection(7, 7, 5, 5)
	d := NewConnectionSet(true)
	d = d.Subtract(c)
	d.AddICMPConnection(7, 7, 5, 5)

	fmt.Println(d.String())

	fmt.Println("done")
}
