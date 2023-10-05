package vpcmodel

func AllConns() *connection.Set {
	return connection.NewSet(true)
}

func NoConns() *connection.Set {
	return connection.NewSet(false)
}

func HasNode(listNodes []Node, node Node) bool {
	for _, n := range listNodes {
		if n.Cidr() == node.Cidr() {
			return true
		}
	}
	return false
}
