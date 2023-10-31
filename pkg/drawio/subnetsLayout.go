package drawio

import (
	"fmt"
	"sort"
	"strings"
)

////////////////////////////////////////////////////////////////////////////////////////////////

type squareSet map[TreeNodeInterface]bool
type squareSetAsKey string

func (sqs *squareSet) asKey() squareSetAsKey {
	ss := []string{}
	for gr := range *sqs {
		ss2 := []string{}
		for _, tn := range gr.(*GroupSubnetsSquareTreeNode).groupedSubnets {
			ss2 = append(ss2, pL(tn.Label()))
		}
		sort.Strings(ss2)
		ss = append(ss, strings.Join(ss2, ""))

	}
	sort.Strings(ss)
	return squareSetAsKey(strings.Join(ss, ","))
}

type miniGroupDataS struct {
	subnets squareSet
	zone    TreeNodeInterface
	groups  []*groupDataS
	located bool
	x, y    int
}
type groupDataS struct {
	miniGroups []*miniGroupDataS
	located    bool
	x1, y1     int
	x2, y2     int
}

// ////////////////////////////////////////////////////////////////////////
func pL(l string) string {
	return l
	l = strings.Split(l, "&")[0]
	ls := strings.Split(l, "-")
	b := []byte{ls[2][0], ls[4][0]}
	l = string(b[:])
	return l
}
func printSubnet(s TreeNodeInterface) string {
	return pL(s.Label())
}
func printGroup(g TreeNodeInterface, h string) string {
	l := h
	for _, subnet := range g.(*GroupSubnetsSquareTreeNode).groupedSubnets {
		l += fmt.Sprint(printSubnet(subnet), ",")
	}
	return "[" + l + "]"
}
func printMiniGroup(mn squareSet, h string) string {
	l := h
	for subnet := range mn {
		l += fmt.Sprint(printSubnet(subnet), ",")
	}
	return "[" + l + "]"
}
func printGroups(gs squareSet) string {
	l := ""
	for g := range gs {
		l += printGroup(g, "")
		l += ","
	}
	return l
}

//////////////////////////////////////////////////////////////////////////

type subnetsLayout struct {
	groups           []*groupDataS
	miniGroups       []*miniGroupDataS
	miniGroupsMatrix [][]*miniGroupDataS
	zoneOrder        []TreeNodeInterface
	zoneIndexOrder   map[TreeNodeInterface]int
	zoneToCol        map[TreeNodeInterface]int
}
func (ly *subnetsLayout)createMatrix(){
	yDim := len(ly.miniGroups)
	xDim := len(ly.miniGroups)

	ly.miniGroupsMatrix = make([][]*miniGroupDataS, yDim)
	for i := range ly.miniGroupsMatrix {
		ly.miniGroupsMatrix[i] = make([]*miniGroupDataS, xDim)
	}

}

func (ly *subnetsLayout) handleGroup(group *groupDataS) {
	handledMiniGroups := []*miniGroupDataS{}
	for _, miniGroup := range group.miniGroups {
		if miniGroup.located {
			continue
		}
		fmt.Println("handling MiniGroup:", printMiniGroup(miniGroup.subnets, ""))
		miniGroup.located = true
		handledMiniGroups = append(handledMiniGroups, miniGroup)
	}
	for _, miniGroup := range handledMiniGroups {
		ly.handleMiniGroup(miniGroup)
	}

}
func (ly *subnetsLayout) handleMiniGroup(miniGroup *miniGroupDataS) {
	for _, group := range miniGroup.groups {
		ly.handleGroup(group)
	}
}

// ////////////////////////////////////////////////////////////////////////
func (ly *subnetsLayout) calcZoneOrder() {
	zoneConnections := map[TreeNodeInterface]map[TreeNodeInterface]int{}
	for _, group := range ly.groups {
		for _, miniGroup1 := range group.miniGroups {
			for _, miniGroup2 := range group.miniGroups {
				if miniGroup1 != miniGroup2 && miniGroup1.zone != miniGroup2.zone {
					if _, ok := zoneConnections[miniGroup1.zone]; !ok {
						zoneConnections[miniGroup1.zone] = map[TreeNodeInterface]int{}
					}
					zoneConnections[miniGroup1.zone][miniGroup2.zone] += 1
				}
			}
		}
	}
	zoneOrder := []TreeNodeInterface{}

	for {

		for i := 1; i < len(zoneOrder)-1; i++ {
			delete(zoneConnections, zoneOrder[i])
		}
		for _, zone := range zoneOrder {
			for _, zScores := range zoneConnections {
				delete(zScores, zone)
			}
		}
		for z, score := range zoneConnections {
			if len(score) == 0 {
				delete(zoneConnections, z)
			}
		}
		if len(zoneConnections) == 0 {
			break
		}

		var zoneToAdd TreeNodeInterface
		addToRight := 1
		if len(zoneOrder) > 0 {
			zonesAtEdges := []TreeNodeInterface{zoneOrder[0], zoneOrder[len(zoneOrder)-1]}
			bestScores := []int{0, 0}
			zonesWithBestScore := []TreeNodeInterface{nil, nil}
			for i, zToChoose := range zonesAtEdges {
				for z, score := range zoneConnections[zToChoose] {
					if bestScores[i] < score {
						bestScores[i] = score
						zonesWithBestScore[i] = z
					}
				}
			}
			if bestScores[0] > bestScores[1] {
				addToRight = 0
			}
			if bestScores[addToRight] > 0 {
				zoneToAdd = zonesWithBestScore[addToRight]
			}

		}
		if zoneToAdd == nil {
			bestScore := 0
			for z, friendsScore := range zoneConnections {
				for _, score := range friendsScore {
					if bestScore < score {
						bestScore = score
						zoneToAdd = z
					}
				}
			}
		}
		if addToRight == 1 {
			zoneOrder = append(zoneOrder, zoneToAdd)
		} else {
			zoneOrder = append([]TreeNodeInterface{zoneToAdd}, zoneOrder...)
		}
	}
	for _, zone := range zoneOrder {
		fmt.Print(" ", zone.Label())
	}
	fmt.Println("")
	ly.zoneOrder = zoneOrder
	ly.zoneIndexOrder = map[TreeNodeInterface]int{}
	for i, z := range zoneOrder {
		ly.zoneIndexOrder[z] = i
	}
}

//////////////////////////////////////////////////////////////////////////

func (ly *subnetsLayout) createMiniGroups(grs []*GroupSubnetsSquareTreeNode) {
	groupedSubnets := squareSet{}
	for _, group := range grs {
		fmt.Println(printGroup(group, "gr:"))
		for _, subnet := range group.groupedSubnets {
			groupedSubnets[subnet] = true
		}

	}
	subnetToGroups := map[TreeNodeInterface]squareSet{}
	for subnet := range groupedSubnets {
		subnetToGroups[subnet] = squareSet{}
	}
	for _, group := range grs {
		for _, subnet := range group.groupedSubnets {
			subnetToGroups[subnet][group] = true
		}
	}
	fmt.Println("subnetToGroups: ")
	groupSetToMiniGroup := map[squareSetAsKey]map[TreeNodeInterface]squareSet{}
	for subnet, groups := range subnetToGroups {
		fmt.Println(printSubnet(subnet), " groups", printGroups(groups))
		if _, ok := groupSetToMiniGroup[groups.asKey()]; !ok {
			groupSetToMiniGroup[groups.asKey()] = map[TreeNodeInterface]squareSet{}
		}
		if _, ok := groupSetToMiniGroup[groups.asKey()][subnet.Parent()]; !ok {
			groupSetToMiniGroup[groups.asKey()][subnet.Parent()] = squareSet{}
		}
		groupSetToMiniGroup[groups.asKey()][subnet.Parent()][subnet] = true
	}
	groupToMiniGroups := map[TreeNodeInterface][]*miniGroupDataS{}
	miniGroups := []*miniGroupDataS{}
	for k, zoneMiniGroup := range groupSetToMiniGroup {
		for zone, miniGroup := range zoneMiniGroup {
			miniGroupData := miniGroupDataS{subnets: miniGroup, zone: zone}
			miniGroups = append(miniGroups, &miniGroupData)
			fmt.Println("miniGroup: ", k, zone.Label(), printMiniGroup(miniGroup, ""))
			for subnet := range miniGroup {
				for group := range subnetToGroups[subnet] {
					groupToMiniGroups[group] = append(groupToMiniGroups[group], &miniGroupData)
				}
			}

		}
	}
	groups := []*groupDataS{}
	for group, miniGroups2 := range groupToMiniGroups {
		groupData := groupDataS{}
		groups = append(groups, &groupData)
		for _, miniGroup := range miniGroups2 {
			groupData.miniGroups = append(groupData.miniGroups, miniGroup)
			miniGroup.groups = append(miniGroup.groups, &groupData)
			fmt.Println(printGroup(group, "group: "), printMiniGroup(miniGroup.subnets, ""))
		}
	}

	sort.Slice(miniGroups, func(i, j int) bool {
		return len(miniGroups[i].groups) > len(miniGroups[j].groups)
	})
	for _, miniGroup := range miniGroups {
		sort.Slice(miniGroup.groups, func(i, j int) bool {
			return len(groups[i].miniGroups) > len(groups[j].miniGroups)
		})
	}
	sort.Slice(groups, func(i, j int) bool {
		return len(groups[i].miniGroups) > len(groups[j].miniGroups)
	})
	ly.groups = groups
	ly.miniGroups = miniGroups
}

//////////////////////////////////////////////////////////////////////////
