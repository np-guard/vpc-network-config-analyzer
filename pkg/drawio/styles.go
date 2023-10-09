//nolint:lll // styles are too long and can not be split
package drawio

import (
	"fmt"
	"reflect"
)

type connParams struct {
	directed bool
	external bool
}

const (
	vsiStyle = "shape=image;aspect=fixed;image=data:image/svg+xml,PHN2ZyBpZD0iTGF5ZXJfMSIgZGF0YS1uYW1lPSJMYXllciAxIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OSA0OSI+PGRlZnM+PHN0eWxlPi5jbHMtMXtmaWxsOiMxOTgwMzg7fS5jbHMtMntmaWxsOiNmZmY7fS5jbHMtM3tmaWxsOm5vbmU7fTwvc3R5bGU+PC9kZWZzPjxyZWN0IGNsYXNzPSJjbHMtMSIgeD0iMC41IiB5PSIwLjUiIHdpZHRoPSI0OCIgaGVpZ2h0PSI0OCIvPjxjaXJjbGUgY2xhc3M9ImNscy0yIiBjeD0iMTguODgiIGN5PSIyOC44OCIgcj0iMC42MyIvPjxyZWN0IGNsYXNzPSJjbHMtMiIgeD0iMTUuNzUiIHk9IjE4LjI1IiB3aWR0aD0iMi41IiBoZWlnaHQ9IjEuMjUiLz48cmVjdCBjbGFzcz0iY2xzLTIiIHg9IjE5LjUiIHk9IjE4LjI1IiB3aWR0aD0iMi41IiBoZWlnaHQ9IjEuMjUiLz48cmVjdCBjbGFzcz0iY2xzLTIiIHg9IjIzLjI1IiB5PSIxOC4yNSIgd2lkdGg9IjIuNSIgaGVpZ2h0PSIxLjI1Ii8+PHJlY3QgY2xhc3M9ImNscy0yIiB4PSIyNyIgeT0iMTguMjUiIHdpZHRoPSIyLjUiIGhlaWdodD0iMS4yNSIvPjxyZWN0IGNsYXNzPSJjbHMtMiIgeD0iMzAuNzUiIHk9IjE4LjI1IiB3aWR0aD0iMi41IiBoZWlnaHQ9IjEuMjUiLz48cGF0aCBjbGFzcz0iY2xzLTIiIGQ9Ik0zMiwzMkgxN2ExLjI1LDEuMjUsMCwwLDEtMS4yNS0xLjI1VjI3QTEuMjUsMS4yNSwwLDAsMSwxNywyNS43NUgzMkExLjI1LDEuMjUsMCwwLDEsMzMuMjUsMjd2My43NUExLjI1LDEuMjUsMCwwLDEsMzIsMzJaTTE3LDI3djMuNzVIMzJWMjdaIi8+PHJlY3QgY2xhc3M9ImNscy0zIiB4PSIxNC41IiB5PSIxNC41IiB3aWR0aD0iMjAiIGhlaWdodD0iMjAiLz48cmVjdCBjbGFzcz0iY2xzLTIiIHg9IjE1Ljc1IiB5PSIyMiIgd2lkdGg9IjE3LjUiIGhlaWdodD0iMS4yNSIvPjwvc3ZnPg==;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;spacingTop=-7;labelPosition=center;verticalLabelPosition=bottom;align=center;verticalAlign=top;"
	fipStyle = "shape=image;aspect=fixed;image=data:image/svg+xml,PHN2ZyBpZD0iTGF5ZXJfMSIgZGF0YS1uYW1lPSJMYXllciAxIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OSA0OSI+PGRlZnM+PHN0eWxlPi5jbHMtMXtmaWxsOiMxMTkyZTg7fS5jbHMtMntmaWxsOiNmZmY7fS5jbHMtM3tmaWxsOm5vbmU7fTwvc3R5bGU+PC9kZWZzPjxyZWN0IGNsYXNzPSJjbHMtMSIgeD0iMC41IiB5PSIwLjkyIiB3aWR0aD0iNDgiIGhlaWdodD0iNDcuMTYiIHJ4PSI4Ii8+PHBhdGggY2xhc3M9ImNscy0yIiBkPSJNMzAuMTIsMjEuNDNhMy4xMywzLjEzLDAsMCwwLTMuMDYsMi40NkgyMS45NGEzLjA3LDMuMDcsMCwxLDAsMCwxLjIyaDUuMTJhMy4xMiwzLjEyLDAsMSwwLDMuMDYtMy42OFptMCw0LjkxQTEuODQsMS44NCwwLDEsMSwzMiwyNC41LDEuODUsMS44NSwwLDAsMSwzMC4xMiwyNi4zNFoiLz48cmVjdCBjbGFzcz0iY2xzLTMiIHg9IjE0LjUiIHk9IjE0LjY3IiB3aWR0aD0iMjAiIGhlaWdodD0iMTkuNjUiLz48L3N2Zz4=;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;labelPosition=center;verticalLabelPosition=bottom;align=center;verticalAlign=top;spacingTop=-7;"
)

func connectivityStyle( con *ConnectivityTreeNode) string{
	startArrow, endArrow := "oval", "oval"
	strokeColor:= ""
	if con.directed{
		endArrow = "block"
	}
	if con.Src().IsGroupingPoint() && !con.Src().(*GroupPointTreeNode).hasShownSquare(){
		startArrow = "none"
	}
	if con.Dst().IsGroupingPoint() && !con.Dst().(*GroupPointTreeNode).hasShownSquare(){
		endArrow = "none"
	}
	if con.router != nil{
		strokeColor = "strokeColor=#007FFF;"
	}
	styleFormat := "endArrow=%s;html=1;fontSize=16;fontColor=#4376BB;strokeWidth=2;endFill=1;rounded=0;startArrow=%s;%sstartFill=1;"
	return fmt.Sprintf(styleFormat, endArrow,startArrow,strokeColor)
}
var styles = map[reflect.Type]string{
	reflect.TypeOf(PublicNetworkTreeNode{}):   "rounded=0;whiteSpace=wrap;html=1;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;spacingBottom=-28;spacingTop=0;labelPosition=-100;verticalLabelPosition=top;align=center;verticalAlign=bottom;spacingLeft=9;spacing=0;expand=0;recursiveResize=0;spacingRight=0;container=1;collapsible=0;strokeColor=#1192E8;fillColor=none;",
	reflect.TypeOf(CloudTreeNode{}):           "rounded=0;whiteSpace=wrap;html=1;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;spacingBottom=-28;spacingTop=0;labelPosition=-100;verticalLabelPosition=top;align=center;verticalAlign=bottom;spacingLeft=9;spacing=0;expand=0;recursiveResize=0;spacingRight=0;container=1;collapsible=0;strokeColor=#1192E8;fillColor=none;",
	reflect.TypeOf(VpcTreeNode{}):             "rounded=0;whiteSpace=wrap;html=1;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;spacingBottom=-28;spacingTop=0;labelPosition=-100;verticalLabelPosition=top;align=center;verticalAlign=bottom;spacingLeft=9;spacing=0;expand=0;recursiveResize=0;spacingRight=0;container=1;collapsible=0;strokeColor=#1192E8;fillColor=none;",
	reflect.TypeOf(ZoneTreeNode{}):            "rounded=0;whiteSpace=wrap;html=1;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;spacingBottom=-28;spacingTop=0;labelPosition=-100;verticalLabelPosition=top;align=center;verticalAlign=bottom;spacingLeft=9;spacing=0;expand=0;recursiveResize=0;spacingRight=0;container=1;collapsible=0;strokeColor=#878d96;fillColor=none;",
	reflect.TypeOf(PartialSGTreeNode{}):       "rounded=0;whiteSpace=wrap;html=1;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;fillColor=none;spacingBottom=-28;spacingTop=0;labelPosition=-100;verticalLabelPosition=top;align=center;verticalAlign=bottom;spacingLeft=9;spacing=0;expand=0;recursiveResize=0;spacingRight=0;container=1;collapsible=0;strokeColor=#FA4D56;strokeWidth=1;",
	reflect.TypeOf(SubnetTreeNode{}):          "rounded=0;whiteSpace=wrap;html=1;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;spacingBottom=-28;spacingTop=0;labelPosition=-100;verticalLabelPosition=top;align=center;verticalAlign=bottom;spacingLeft=9;spacing=0;expand=0;recursiveResize=0;spacingRight=0;container=1;collapsible=0;strokeColor=#1192E8;fillColor=none;",
	reflect.TypeOf(GroupSquareTreeNode{}):     "rounded=1;whiteSpace=wrap;html=1;fillColor=none;strokeColor=#006633;strokeWidth=1;perimeterSpacing=0;arcSize=12;",
	reflect.TypeOf(NITreeNode{}):              "shape=image;aspect=fixed;image=data:image/svg+xml,PHN2ZyBpZD0iTGF5ZXJfMSIgZGF0YS1uYW1lPSJMYXllciAxIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OSA0OSI+CjxkZWZzPgo8c3R5bGU+LmNscy0xe2ZpbGw6I2VlNTM5Njt9LmNscy0ye2ZpbGw6bm9uZTt9LmNscy0ze2ZpbGw6I2ZmZjt9PC9zdHlsZT4KPC9kZWZzPg0KPHJlY3QgY2xhc3M9ImNscy0xIiB4PSIwLjUiIHk9IjAuNSIgd2lkdGg9IjQ4IiBoZWlnaHQ9IjQ4Ii8+CjxyZWN0IGNsYXNzPSJjbHMtMiIgeD0iMTQuNSIgeT0iMTQuNSIgd2lkdGg9IjIwIiBoZWlnaHQ9IjIwIi8+DQo8dGV4dCBmb250LXNpemU9IjMwIiBmaWxsPSJ3aGl0ZSIgeD0iOCIgeT0iMzUiPk5JPC90ZXh0Pgo8L3N2Zz4=;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;labelPosition=center;verticalLabelPosition=bottom;align=center;verticalAlign=top;spacingTop=-7;",
	reflect.TypeOf(VsiTreeNode{}):             vsiStyle,
	reflect.TypeOf(GroupPointTreeNode{}):      "ellipse;whiteSpace=wrap;html=1;aspect=fixed;",
	reflect.TypeOf(UserTreeNode{}):            "shape=image;aspect=fixed;image=data:image/svg+xml,PHN2ZyBpZD0iTGF5ZXJfMSIgZGF0YS1uYW1lPSJMYXllciAxIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OSA0OSI+PGRlZnM+PHN0eWxlPi5jbHMtMXtmaWxsOm5vbmU7fS5jbHMtMntmaWxsOiNmZmY7ZmlsbC1ydWxlOmV2ZW5vZGQ7fTwvc3R5bGU+PC9kZWZzPjxyZWN0IHg9IjAuNSIgeT0iMC41IiB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHJ4PSIyNCIvPjxyZWN0IGNsYXNzPSJjbHMtMSIgeD0iMTQuNSIgeT0iMTQuNSIgd2lkdGg9IjIwIiBoZWlnaHQ9IjIwIi8+PHBhdGggaWQ9IkZpbGwtMyIgY2xhc3M9ImNscy0yIiBkPSJNMzAuOCwzMy44N0gyOVYyOS41OUEyLjYzLDIuNjMsMCwwLDAsMjYuMywyN0gyMi43QTIuNjMsMi42MywwLDAsMCwyMCwyOS41OXY0LjI4SDE4LjJWMjkuNTlhNC40MSw0LjQxLDAsMCwxLDQuNS00LjI4aDMuNmE0LjQxLDQuNDEsMCwwLDEsNC41LDQuMjhaIi8+PHBhdGggaWQ9IkZpbGwtNSIgY2xhc3M9ImNscy0yIiBkPSJNMjQuNSwxNS4wNUE0LjM5LDQuMzksMCwwLDAsMjAsMTkuMzNhNC41MSw0LjUxLDAsMCwwLDksMCw0LjM5LDQuMzksMCwwLDAtNC41LTQuMjhtMCwxLjcxYTIuNTcsMi41NywwLDEsMS0yLjcsMi41NywyLjY0LDIuNjQsMCwwLDEsMi43LTIuNTciLz48L3N2Zz4=;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;labelPosition=center;verticalLabelPosition=bottom;align=center;verticalAlign=top;spacingTop=-7;",
	reflect.TypeOf(GatewayTreeNode{}):         "shape=image;aspect=fixed;image=data:image/svg+xml,PHN2ZyBpZD0iTGF5ZXJfMSIgZGF0YS1uYW1lPSJMYXllciAxIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OSA0OSI+PGRlZnM+PHN0eWxlPi5jbHMtMXtmaWxsOiMxMTkyZTg7fS5jbHMtMntmaWxsOiNmZmY7fS5jbHMtM3tmaWxsOm5vbmU7fTwvc3R5bGU+PC9kZWZzPjxyZWN0IGNsYXNzPSJjbHMtMSIgeD0iMC41IiB5PSIwLjUiIHdpZHRoPSI0OCIgaGVpZ2h0PSI0OCIgcng9IjgiLz48cGF0aCBjbGFzcz0iY2xzLTIiIGQ9Ik0zMy41MSwyNS4zOGExLjIzLDEuMjMsMCwwLDAsMC0xLjc2TDI5Ljg5LDIwbDEuODEtMS43OWExLjI1LDEuMjUsMCwxLDAtLjU4LTIuMDksMS4yMiwxLjIyLDAsMCwwLS4zMiwxLjIyTDI5LDE5LjEybC0zLjYzLTMuNjNhMS4yMywxLjIzLDAsMCwwLTEuNzYsMEwyMCwxOS4xMWwtMS43OS0xLjgyYTEuMjQsMS4yNCwwLDEsMC0yLjA5LjU5LDEuMjIsMS4yMiwwLDAsMCwxLjIyLjMyTDE5LjEyLDIwbC0zLjYzLDMuNjNhMS4yMywxLjIzLDAsMCwwLDAsMS43NkwxOS4xMiwyOSwxNy4zNCwzMC44YTEuMjIsMS4yMiwwLDAsMC0xLjIyLjMyLDEuMjQsMS4yNCwwLDEsMCwyLjA5LjU5TDIwLDI5Ljg5bDMuNjIsMy42MmExLjIzLDEuMjMsMCwwLDAsMS43NiwwTDI5LDI5Ljg4bDEuNzksMS43OGExLjIyLDEuMjIsMCwwLDAsLjMyLDEuMjIsMS4yNCwxLjI0LDAsMSwwLC41OC0yLjA5TDI5Ljg5LDI5Wm0tOSw3LjI0TDE2LjM4LDI0LjVsOC4xMi04LjEyLDguMTIsOC4xMloiLz48cmVjdCBjbGFzcz0iY2xzLTMiIHg9IjE0LjUiIHk9IjE0LjUiIHdpZHRoPSIyMCIgaGVpZ2h0PSIyMCIvPjxwYXRoIGNsYXNzPSJjbHMtMiIgZD0iTTI2LjM4LDIzLjI1SDIzLjI1VjIyYTEuMjUsMS4yNSwwLDAsMSwyLjUsMEgyN2EyLjUsMi41LDAsMCwwLTUsMHYxLjQyYTEuMjYsMS4yNiwwLDAsMC0uNjIsMS4wOHYzLjEyYTEuMjYsMS4yNiwwLDAsMCwxLjI0LDEuMjZoMy43NmExLjI2LDEuMjYsMCwwLDAsMS4yNC0xLjI2VjI0LjVBMS4yNSwxLjI1LDAsMCwwLDI2LjM4LDIzLjI1Wm0wLDQuMzdIMjIuNjJWMjQuNWgzLjc2WiIvPjwvc3ZnPg==;fontSize=14;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;spacingTop=-7;labelPosition=center;verticalLabelPosition=bottom;align=center;verticalAlign=top;",
	reflect.TypeOf(InternetTreeNode{}):        "shape=image;aspect=fixed;image=data:image/svg+xml,PHN2ZyBpZD0iTGF5ZXJfMSIgZGF0YS1uYW1lPSJMYXllciAxIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OSA0OSI+PGRlZnM+PHN0eWxlPi5jbHMtMXtmaWxsOiMxMTkyZTg7fS5jbHMtMntmaWxsOiNmZmY7fS5jbHMtM3tmaWxsOm5vbmU7fTwvc3R5bGU+PC9kZWZzPjxyZWN0IGNsYXNzPSJjbHMtMSIgeD0iMC41IiB5PSIwLjUiIHdpZHRoPSI0OCIgaGVpZ2h0PSI0OCIgcng9IjgiLz48cGF0aCBjbGFzcz0iY2xzLTIiIGQ9Ik0yNC41LDE1Ljc1YTguNzUsOC43NSwwLDEsMCw4Ljc1LDguNzVBOC43NSw4Ljc1LDAsMCwwLDI0LjUsMTUuNzVaTTMyLDIzLjg4SDI4LjI1YTE1LjE5LDE1LjE5LDAsMCwwLTEuNzQtNi42QTcuNSw3LjUsMCwwLDEsMzIsMjMuODhaTTI0LjUsMzJoLS40MkExMy43MiwxMy43MiwwLDAsMSwyMiwyNS4xMmg1QTEzLjYzLDEzLjYzLDAsMCwxLDI0Ljk0LDMyWk0yMiwyMy44OEExMy42MywxMy42MywwLDAsMSwyNC4wNiwxN2EzLjkzLDMuOTMsMCwwLDEsLjg0LDBBMTMuNjQsMTMuNjQsMCwwLDEsMjcsMjMuODhabS40OC02LjZhMTUuMTgsMTUuMTgsMCwwLDAtMS43Myw2LjZIMTdhNy41LDcuNSwwLDAsMSw1LjQ5LTYuNlpNMTcsMjUuMTJoMy43NWExNS4yLDE1LjIsMCwwLDAsMS43Miw2LjZBNy41Miw3LjUyLDAsMCwxLDE3LDI1LjEyWm05LjQ4LDYuNmExNS4xOSwxNS4xOSwwLDAsMCwxLjc0LTYuNkgzMkE3LjUsNy41LDAsMCwxLDI2LjUxLDMxLjcyWiIvPjxyZWN0IGlkPSJfVHJhbnNwYXJlbnRfUmVjdGFuZ2xlXyIgZGF0YS1uYW1lPSIgVHJhbnNwYXJlbnQgUmVjdGFuZ2xlICIgY2xhc3M9ImNscy0zIiB4PSIxNC41IiB5PSIxNC41IiB3aWR0aD0iMjAiIGhlaWdodD0iMjAiLz48L3N2Zz4=;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;labelPosition=center;verticalLabelPosition=bottom;align=center;verticalAlign=top;spacingTop=-7;",
	reflect.TypeOf(InternetServiceTreeNode{}): "shape=image;aspect=fixed;image=data:image/svg+xml,PHN2ZyBpZD0iTGF5ZXJfMSIgZGF0YS1uYW1lPSJMYXllciAxIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OSA0OSI+PGRlZnM+PHN0eWxlPi5jbHMtMXtmaWxsOiMxMTkyZTg7fS5jbHMtMntmaWxsOiNmZmY7fS5jbHMtM3tmaWxsOm5vbmU7fTwvc3R5bGU+PC9kZWZzPjxyZWN0IGNsYXNzPSJjbHMtMSIgeD0iMC41IiB5PSIwLjUiIHdpZHRoPSI0OCIgaGVpZ2h0PSI0OCIvPjxwYXRoIGNsYXNzPSJjbHMtMiIgZD0iTTMxLjg3LDIwLjc1YTYuMjUsNi4yNSwwLDAsMC0xMi4yNi4wOCw0LjY4LDQuNjgsMCwwLDAsLjgzLDkuMjloLjk0VjI4Ljg3aC0uOTRBMy40MywzLjQzLDAsMCwxLDIwLjIsMjJsLjUyLDAsLjA2LS41MmE1LDUsMCwwLDEsOS44MS0uNzFaIi8+PHJlY3QgY2xhc3M9ImNscy0zIiB4PSIxNC41IiB5PSIxNC41IiB3aWR0aD0iMjAiIGhlaWdodD0iMjAiLz48cGF0aCBjbGFzcz0iY2xzLTIiIGQ9Ik0zMS4zNywyOS41YTEuODQsMS44NCwwLDAsMC0xLjIuNDVsLTIuNTYtMS41NGMwLS4wNSwwLS4xLDAtLjE2czAtLjExLDAtLjE2bDIuNTYtMS41NGExLjg2LDEuODYsMCwwLDAsMS4yLjQ1LDEuODgsMS44OCwwLDEsMC0xLjg3LTEuODgsMS40MiwxLjQyLDAsMCwwLDAsLjM2bC0yLjQ1LDEuNDZhMS44NiwxLjg2LDAsMCwwLTEuMzQtLjU3LDEuODgsMS44OCwwLDAsMCwwLDMuNzUsMS44NSwxLjg1LDAsMCwwLDEuMzQtLjU2TDI5LjU0LDMxYTEuNDUsMS40NSwwLDAsMCwwLC4zNSwxLjg4LDEuODgsMCwxLDAsMS44Ny0xLjg3Wm0wLTVhLjYzLjYzLDAsMSwxLS42Mi42MkEuNjMuNjMsMCwwLDEsMzEuMzcsMjQuNVptLTUuNjIsNC4zN2EuNjMuNjMsMCwwLDEtLjYzLS42Mi42NC42NCwwLDAsMSwuNjMtLjYzLjYzLjYzLDAsMCwxLC42Mi42M0EuNjIuNjIsMCwwLDEsMjUuNzUsMjguODdaTTMxLjM3LDMyYS42My42MywwLDEsMSwuNjMtLjYzQS42My42MywwLDAsMSwzMS4zNywzMloiLz48L3N2Zz4=;fontSize=14;labelPosition=center;verticalLabelPosition=bottom;align=center;verticalAlign=top;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;spacingTop=-6;",
	reflect.TypeOf(VsiLineTreeNode{}):         "html=1;verticalAlign=middle;startArrow=oval;startFill=1;endArrow=oval;startSize=6;strokeColor=#000000;align=center;dashed=1;strokeWidth=2;horizontal=1;labelPosition=center;verticalLabelPosition=middle;endFill=1;rounded=0;",
	// reflect.TypeOf(EndPointTreeNode{}):        "shape=image;aspect=fixed;image=data:image/svg+xml,PHN2ZyBpZD0iTGF5ZXJfMSIgZGF0YS1uYW1lPSJMYXllciAxIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OSA0OSI+PGRlZnM+PHN0eWxlPi5jbHMtMXtmaWxsOiMxMTkyZTg7fS5jbHMtMntmaWxsOiNmZmY7fS5jbHMtM3tmaWxsOm5vbmU7fTwvc3R5bGU+PC9kZWZzPjxyZWN0IGNsYXNzPSJjbHMtMSIgeD0iMC41IiB5PSIwLjUiIHdpZHRoPSI0OCIgaGVpZ2h0PSI0OCIvPjxwYXRoIGlkPSJ2cGNfZ3JhZGllbnRfYm90dG9tIiBkYXRhLW5hbWU9InZwYyBncmFkaWVudCBib3R0b20iIGNsYXNzPSJjbHMtMiIgZD0iTTI3LDMxLjM4SDE4Ljg4YTEuMjcsMS4yNywwLDAsMS0xLjI2LTEuMjVWMjJoMS4yNnY4LjEzSDI3WiIvPjxwYXRoIGlkPSJ2cGNfZ3JhZGllbnRfdG9wIiBkYXRhLW5hbWU9InZwYyBncmFkaWVudCB0b3AiIGNsYXNzPSJjbHMtMiIgZD0iTTMwLjEyLDI3aDEuMjZWMTguODhhMS4yNiwxLjI2LDAsMCwwLTEuMjYtMS4yNUgyMnYxLjI1aDguMTJaIi8+PHBhdGggaWQ9ImVuZHBvaW50cyIgY2xhc3M9ImNscy0yIiBkPSJNMjkuMTIsMjguMjVsLTIuNS0yLjVBMi4yNiwyLjI2LDAsMCwwLDI3LDI0LjUsMi41MSwyLjUxLDAsMCwwLDI0LjUsMjJhMi4xOSwyLjE5LDAsMCwwLTEuMjUuMzhsLTIuNS0yLjVWMTUuNzVoLTV2NWg0LjEzbDIuNSwyLjVBMi4yNiwyLjI2LDAsMCwwLDIyLDI0LjUsMi41MSwyLjUxLDAsMCwwLDI0LjUsMjdhMi4yNiwyLjI2LDAsMCwwLDEuMjUtLjM4bDIuNSwyLjV2NC4xM2g1di01Wk0xOS41LDE5LjVIMTdWMTdoMi41Wm01LDYuMjVhMS4yNSwxLjI1LDAsMSwxLDEuMjUtMS4yNUExLjI1LDEuMjUsMCwwLDEsMjQuNSwyNS43NVpNMzIsMzJIMjkuNVYyOS41SDMyWiIvPjxyZWN0IGNsYXNzPSJjbHMtMyIgeD0iMTQuNSIgeT0iMTQuNSIgd2lkdGg9IjIwIiBoZWlnaHQ9IjIwIi8+PC9zdmc+;fontSize=14;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;spacingTop=-7;labelPosition=center;verticalLabelPosition=bottom;align=center;verticalAlign=top;",
}
var tagStyles = map[reflect.Type]string{
	reflect.TypeOf(PublicNetworkTreeNode{}): "shape=image;aspect=fixed;image=data:image/svg+xml,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iMjlweCIgaGVpZ2h0PSIyNnB4IiB2aWV3Qm94PSIwIDAgMjkgMjYiIHZlcnNpb249IjEuMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI+CiAgICA8IS0tIEdlbmVyYXRvcjogU2tldGNoIDUzICg3MjUyMCkgLSBodHRwczovL3NrZXRjaGFwcC5jb20gLS0+CiAgICA8dGl0bGU+UHVibGljIE5ldHdvcmsgQmxhY2s8L3RpdGxlPgogICAgPGRlc2M+Q3JlYXRlZCB3aXRoIFNrZXRjaC48L2Rlc2M+CiAgICA8ZyBpZD0iUGFnZS0xIiBzdHJva2U9Im5vbmUiIHN0cm9rZS13aWR0aD0iMSIgZmlsbD0ibm9uZSIgZmlsbC1ydWxlPSJldmVub2RkIj4KICAgICAgICA8ZyBpZD0iUHVibGljLU5ldHdvcmstQmxhY2siIHRyYW5zZm9ybT0idHJhbnNsYXRlKDAuOTAxMTA2LCAtMC4xNzQyMzMpIiBmaWxsPSIjMDAwMDAwIj4KICAgICAgICAgICAgPGcgaWQ9IkludGVybmV0IiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgxMS44Njc1NTksIDEwLjExMTEyMykiPgogICAgICAgICAgICAgICAgPHBhdGggZD0iTTkuOTQwMzIwMTEsMTQuMjczNTIwNyBDMTAuOTEwMDkwMywxMi40MzQ5NjI3IDExLjQ0ODI4NzQsMTAuMzk5NTE3MSAxMS41MTQyOTI3LDguMzIxNzYwMzkgTDE0Ljg5OTE4MDEsOC4zMjE3NjAzOSBDMTQuNjU3MTYwNywxMS4xNDg3MDU1IDEyLjY3NzU2NTcsMTMuNTI0ODk2NCA5Ljk0MDMyMDExLDE0LjI3MzUyMDcgTDkuOTQwMzIwMTEsMTQuMjczNTIwNyBaIE0xLjM4NzgzODAzLDguMzIxNzYwMzkgTDQuNzcyNzI1NCw4LjMyMTc2MDM5IEM0LjgzMTk2MDkyLDEwLjM5NzgyNDYgNS4zNjIyNTk5NSwxMi40MzMyNzAzIDYuMzI0MTMyMTEsMTQuMjczNTIwNyBDMy41OTU5MTI4OSwxMy41MTY5OTg0IDEuNjI3MDM2NzMsMTEuMTQzMDY0IDEuMzg3ODM4MDMsOC4zMjE3NjAzOSBMMS4zODc4MzgwMyw4LjMyMTc2MDM5IFogTTYuNDA2NDk3NywxLjU1MTk4NTY1IEM1LjQwMTc1MDMsMy40NzA2NTI2NSA0Ljg0NjYyODc3LDUuNTkyOTc3MDMgNC43ODM0NDQyMSw3Ljc1NzYxMjUgTDEuMjU0MTM0OTgsNy43NTc2MTI1IEMxLjUwNjg3MzIzLDQuODA5OTM5NzUgMy41NzA1MjYyMywyLjMzMjc2NjM0IDYuNDI0NTUwNDMsMS41NTE5ODU2NSBMNi40MDY0OTc3LDEuNTUxOTg1NjUgWiBNNS44NzI4MTM3OSw3LjE5MzQ2NDYgQzUuOTI5MjI4NTgsNC45OTYxMDg1NSA2LjU3MTc5MzAzLDIuODUzNDc0ODUgNy43MzQ1MDE4NCwwLjk4NzgzNzc2IEM3Ljk4NjExMTgsMC45NTk2MzAzNjUgOC4yMzk0MTQyMSwwLjk1OTYzMDM2NSA4LjQ5MDQ2MDAyLDAuOTg3ODM3NzYgQzkuNjY1NTgwMDksMi44NTAwODk5NiAxMC4zMTk5OTE2LDQuOTkyNzIzNjcgMTAuMzg1OTk2OSw3LjE5MzQ2NDYgTDUuODcyODEzNzksNy4xOTM0NjQ2IFogTTguMTI5NDA1MzcsMTQuNTI3Mzg3MiBDOC4wMDM2MDAzOSwxNC41MzU4NDk1IDcuODc3MjMxMjYsMTQuNTM1ODQ5NSA3Ljc1MTQyNjI4LDE0LjUyNzM4NzIgQzYuNTgyNTExODQsMTIuNjYzNDQyNiA1LjkzNDMwNTkxLDEwLjUyMDgwODkgNS44NzI4MTM3OSw4LjMyMTc2MDM5IEwxMC4zODU5OTY5LDguMzIxNzYwMzkgQzEwLjMzMDE0NjMsMTAuNTE5NjgwNiA5LjY4NzAxNzcxLDEyLjY2MjMxNDMgOC41MjQzMDg5LDE0LjUyNzM4NzIgQzguMzkyODYyNDQsMTQuNTM2NDEzNiA4LjI2MDg1MTgzLDE0LjUzNjQxMzYgOC4xMjk0MDUzNywxNC41MjczODcyIEw4LjEyOTQwNTM3LDE0LjUyNzM4NzIgWiBNMTQuODk5MTgwMSw3LjE5MzQ2NDYgTDExLjUxNDI5MjcsNy4xOTM0NjQ2IEMxMS40NDgyODc0LDUuMTE1NzA3OTEgMTAuOTEwMDkwMywzLjA4MDI2MjMgOS45NDAzMjAxMSwxLjI0MTcwNDMxIEMxMi42Nzc1NjU3LDEuOTkwMzI4NTcgMTQuNjU3MTYwNyw0LjM2NjUxOTUgMTQuODk5MTgwMSw3LjE5MzQ2NDYgTDE0Ljg5OTE4MDEsNy4xOTM0NjQ2IFogTTguMTI5NDA1MzcsMC4xMzcxMDI3MzQgQzMuNzY3NDEzODUsMC4xMzcxMDI3MzQgMC4yMzEzMzQ4NDIsMy42NzMxODE3NCAwLjIzMTMzNDg0Miw4LjAzNTE3MzI2IEMwLjIzMTMzNDg0MiwxMi4zOTcxNjQ4IDMuNzY3NDEzODUsMTUuOTMzMjQzOCA4LjEyOTQwNTM3LDE1LjkzMzI0MzggQzEyLjQ5MTM5NjksMTUuOTMzMjQzOCAxNi4wMjc0NzU5LDEyLjM5NzE2NDggMTYuMDI3NDc1OSw4LjAzNTE3MzI2IEMxNi4wMjc0NzU5LDMuNjczMTgxNzQgMTIuNDkxMzk2OSwwLjEzNzEwMjczNCA4LjEyOTQwNTM3LDAuMTM3MTAyNzM0IEw4LjEyOTQwNTM3LDAuMTM3MTAyNzM0IFoiIGlkPSJGaWxsLTEiPjwvcGF0aD4KICAgICAgICAgICAgPC9nPgogICAgICAgICAgICA8ZyBpZD0iQ2xhc3NpYy1JbmZyYXN0cnVjdHVyZS1CbGFjay1Db3B5Ij4KICAgICAgICAgICAgICAgIDxnIGlkPSJHcm91cC02IiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgwLjAwMDAwMCwgMC45OTg0MDApIj4KICAgICAgICAgICAgICAgICAgICA8cGF0aCBkPSJNMTIuMDAwMDIxMiwyMi45OTgwNDIyIEw3LjczNzAyMTE4LDIyLjk5ODA0MjIgQzQuMTQ2MDIxMTgsMjIuOTk4MDQyMiAwLjg3OTAyMTE4MiwyMC41NzkwNDIyIDAuMTU5MDIxMTgyLDE3LjA2MTA0MjIgQy0wLjcxMjk3ODgxOCwxMi43OTQwNDIyIDIuMTAwMDIxMTgsOC44NTEwNDIyMiA2LjE3ODAyMTE4LDguMTIyMDQyMjIgQzcuMjE2MDIxMTgsMi42OTgwNDIyMiAxMi40NTUwMjEyLC0wLjg1Nzk1Nzc4MyAxNy44NzkwMjEyLDAuMTgwMDQyMjE3IEMyMi41OTEwMjEyLDEuMDgxMDQyMjIgMjUuOTk5MDIxMiw1LjIwMTA0MjIyIDI2LjAwMDAyMTIsOS45OTgwNDIyMiBMMjQuMDAwMDIxMiw5Ljk5ODA0MjIyIEMyNC4wMDEwMjEyLDUuMTAwMDQyMjIgMTkuNTk5MDIxMiwxLjIyOTA0MjIyIDE0LjUzNDAyMTIsMi4xMjgwNDIyMiBDMTAuOTk5MDIxMiwyLjc1NjA0MjIyIDguNDA2MDIxMTgsNS44MjYwNDIyMiA4LjAyMTAyMTE4LDkuMzk2MDQyMjIgTDcuOTU5MDIxMTgsOS45NjEwNDIyMiBMNy4zMTMwMjExOCwxMC4wMDUwNDIyIEM0Ljc0MDAyMTE4LDEwLjE3OTA0MjIgMi40NzcwMjExOCwxMi4wMjIwNDIyIDIuMDcwMDIxMTgsMTQuNTY5MDQyMiBDMS41MTIwMjExOCwxOC4wNTcwNDIyIDQuMTgyMDIxMTgsMjEuMDAzMDQyMiA3LjUwMDAyMTE4LDIwLjk5ODA0MjIgTDEyLjAwMDAyMTIsMjAuOTk4MDQyMiBMMTIuMDAwMDIxMiwyMi45OTgwNDIyIFoiIGlkPSJGaWxsLTQiPjwvcGF0aD4KICAgICAgICAgICAgICAgIDwvZz4KICAgICAgICAgICAgPC9nPgogICAgICAgIDwvZz4KICAgIDwvZz4KPC9zdmc+;",
	reflect.TypeOf(CloudTreeNode{}):         "shape=image;aspect=fixed;image=data:image/svg+xml,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iMzNweCIgaGVpZ2h0PSIzMXB4IiB2aWV3Qm94PSIwIDAgMzMgMzEiIHZlcnNpb249IjEuMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI+CiAgICA8IS0tIEdlbmVyYXRvcjogU2tldGNoIDUzICg3MjUyMCkgLSBodHRwczovL3NrZXRjaGFwcC5jb20gLS0+CiAgICA8dGl0bGU+SUJNIENsb3VkIEJsYWNrPC90aXRsZT4KICAgIDxkZXNjPkNyZWF0ZWQgd2l0aCBTa2V0Y2guPC9kZXNjPgogICAgPGcgaWQ9IlBhZ2UtMSIgc3Ryb2tlPSJub25lIiBzdHJva2Utd2lkdGg9IjEiIGZpbGw9Im5vbmUiIGZpbGwtcnVsZT0iZXZlbm9kZCI+CiAgICAgICAgPGcgaWQ9IklCTS1DbG91ZC1CbGFjayIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMC43ODQ3MjIsIDAuNTAwMTI1KSIgZmlsbD0iIzAwMDAwMCI+CiAgICAgICAgICAgIDxwYXRoIGQ9Ik0yNy4xMDIxLDI3LjAxMDYgQzI1Ljg3MDEsMjcuODc5NiAyNC4zNjExLDI4LjI2NzYgMjIuODUzMSwyOC4yNjc2IEw3LjAwNDEsMjguMjY3NiBDNC4xMTIxLDI4LjI3NDYgMS43NjIxLDI1LjkzNDYgMS43NTUxLDIzLjA0MjYgQzEuNzQ5MSwyMC40MTA2IDMuNjk3MSwxOC4xODM2IDYuMzA1MSwxNy44Mzg2IEM2LjQxMTEsMTkuMTYxNiA2Ljc4NzEsMjAuNDQ5NiA3LjQwOTEsMjEuNjIxNiBDNy41OTUxLDIxLjk5MTYgOC4wNDYxLDIyLjE0MDYgOC40MTYxLDIxLjk1NDYgQzguNzg2MSwyMS43Njc2IDguOTM1MSwyMS4zMTc2IDguNzQ4MSwyMC45NDc2IEw4LjczMDEsMjAuOTEyNiBDNy4xMzIxLDE3LjkzNTYgNy40MjkxLDE0LjIxNzYgOS42NzIxLDExLjY4OTYgQzEzLjQ4NjEsNy4zOTI2IDE5Ljc4NzEsOC4wNTI2IDIyLjc1NzEsMTIuMjgxNiBDMjAuMzM0MSwxMi4zNDc2IDE4LjA0NzEsMTMuNDE1NiAxNi40NDExLDE1LjIzMDYgQzE2LjE2MTEsMTUuNTM1NiAxNi4xODExLDE2LjAxMDYgMTYuNDg1MSwxNi4yOTA2IEMxNi43ODkxLDE2LjU3MTYgMTcuMjY0MSwxNi41NTI2IDE3LjU0NTEsMTYuMjQ3NiBMMTcuNTY2MSwxNi4yMjI2IEMxOS41OTUxLDEzLjkyMzYgMjIuODg0MSwxMy4wNTI2IDI1LjcwMzEsMTQuMjYzNiBDMzEuMTY1MSwxNi42MDk2IDMxLjgxMDEsMjMuNjkyNiAyNy4xMDIxLDI3LjAxMDYgTTI0LjU4NTEsMTIuOTE3NiBDMjIuMDU0MSw4LjE3NTYgMTYuMTU5MSw2LjM4MjYgMTEuNDE2MSw4LjkxMzYgQzguNDY1MSwxMC40ODg2IDYuNTI5MSwxMy40Njg2IDYuMjkwMSwxNi44MDY2IEMyLjU4NDEsMTcuMjA0NiAtMC4wOTc5LDIwLjUzMjYgMC4zMDExLDI0LjIzOTYgQzAuNjY5MSwyNy42NjU2IDMuNTU5MSwzMC4yNjM2IDcuMDA0MSwzMC4yNjc2IEwyMy4wMDQxLDMwLjI2NzYgQzI3LjgzNTEsMzAuMjcwNiAzMS43NTMxLDI2LjM1NzYgMzEuNzU2MSwyMS41MjY2IEMzMS43NTkxLDE3LjMwMTYgMjguNzQxMSwxMy42Nzg2IDI0LjU4NTEsMTIuOTE3NiIgaWQ9IkZpbGwtMSI+PC9wYXRoPgogICAgICAgICAgICA8ZyBpZD0iR3JvdXAtNSIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMjcuMDAwMDAwLCA4LjI2NzcwMCkiPgogICAgICAgICAgICAgICAgPHBhdGggZD0iTTQuOTAyOCwwLjkxOTcgQzQuNjkzOCwwLjU1NjcgNC4yMjk4LDAuNDMyNyAzLjg2NjgsMC42NDE3IEMzLjg2NjgsMC42NDE3IDMuODY2OCwwLjY0MTcgMy44NjY4LDAuNjQyNyBMMC44NDY4LDIuMzg1NyBDMC40Nzg4LDIuNTg2NyAwLjM0MzgsMy4wNDc3IDAuNTQ0OCwzLjQxNTcgQzAuNzQ1OCwzLjc4MzcgMS4yMDY4LDMuOTE4NyAxLjU3NDgsMy43MTc3IEMxLjU4NDgsMy43MTE3IDEuNTk0OCwzLjcwNTcgMS42MDQ4LDMuNjk5NyBMNC42MjQ4LDEuOTU2NyBDNC45ODc4LDEuNzQ2NyA1LjExMTgsMS4yODI3IDQuOTAyOCwwLjkxOTciIGlkPSJGaWxsLTMiPjwvcGF0aD4KICAgICAgICAgICAgPC9nPgogICAgICAgICAgICA8cGF0aCBkPSJNMjIuNjgxMiw2LjgwMjYgQzIzLjA0MzIsNy4wMTI2IDIzLjUwNzIsNi44ODg2IDIzLjcxNzIsNi41MjU2IEwyMy43MTcyLDYuNTI1NiBMMjUuNDYxMiwzLjUwNTYgQzI1LjY2ODIsMy4xNDA2IDI1LjU0MDIsMi42Nzc2IDI1LjE3NjIsMi40NzA2IEMyNC44MTUyLDIuMjY2NiAyNC4zNTcyLDIuMzg4NiAyNC4xNDcyLDIuNzQ2NiBMMjIuNDAzMiw1Ljc2NjYgQzIyLjE5NDIsNi4xMjk2IDIyLjMxODIsNi41OTM2IDIyLjY4MTIsNi44MDI2IiBpZD0iRmlsbC02Ij48L3BhdGg+CiAgICAgICAgICAgIDxwYXRoIGQ9Ik0xNi4wMDQ0LDUuMDE0MSBDMTYuNDIzNCw1LjAxNDEgMTYuNzYzNCw0LjY3NDEgMTcuMzM1NCw0LjI1NTEgTDE3LjMzNTQsMC43NjcxIEMxNi43Njg0LDAuMzQ4MSAxNi40MzI0LDAuMDA1MSAxNi4wMTM0LDAuMDAwMSBDMTUuNTk0NCwtMC4wMDQ5IDE1LjI1MTQsMC4zMzExIDE1LjMzNTQsMC43NTAxIEwxNS4zMzU0LDAuNzY3MSBMMTUuMzM1NCw0LjI1NTEgQzE1LjI0NjQsNC42NzQxIDE1LjU4NTQsNS4wMTQxIDE2LjAwNDQsNS4wMTQxIiBpZD0iRmlsbC04Ij48L3BhdGg+CiAgICAgICAgICAgIDxwYXRoIGQ9Ik04LjI5Miw2LjUyNDggQzguNTA0LDYuODg1OCA4Ljk2OSw3LjAwNjggOS4zMzEsNi43OTQ4IEM5LjY4OCw2LjU4NDggOS44MTEsNi4xMjY4IDkuNjA2LDUuNzY1OCBMNy44NjIsMi43NDU4IEM3LjY1NSwyLjM4MTggNy4xOTIsMi4yNTM4IDYuODI4LDIuNDYwOCBDNi40NjMsMi42Njc4IDYuMzM1LDMuMTMwOCA2LjU0MiwzLjQ5NDggQzYuNTQ0LDMuNDk4OCA2LjU0NiwzLjUwMTggNi41NDgsMy41MDQ4IEw4LjI5Miw2LjUyNDggWiIgaWQ9IkZpbGwtMTAiPjwvcGF0aD4KICAgICAgICAgICAgPGcgaWQ9Ikdyb3VwLTE0IiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgwLjAwMDAwMCwgOC4yNjc3MDApIj4KICAgICAgICAgICAgICAgIDxwYXRoIGQ9Ik00LjE2MzEsMi4zODYgTDEuMTQzMSwwLjY0MiBDMC43ODIxLDAuNDMgMC4zMTcxLDAuNTUxIDAuMTA0MSwwLjkxMiBDLTAuMTA3OSwxLjI3MyAwLjAxMzEsMS43MzkgMC4zNzQxLDEuOTUgQzAuMzc4MSwxLjk1MiAwLjM4MTEsMS45NTQgMC4zODQxLDEuOTU2IEwzLjQwNTEsMy43IEMzLjc2NjEsMy45MTIgNC4yMzExLDMuNzkxIDQuNDQzMSwzLjQzIEM0LjY1NTEsMy4wNjkgNC41MzUxLDIuNjA0IDQuMTczMSwyLjM5MiBDNC4xNzAxLDIuMzkgNC4xNjYxLDIuMzg4IDQuMTYzMSwyLjM4NiBaIiBpZD0iRmlsbC0xMiI+PC9wYXRoPgogICAgICAgICAgICA8L2c+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4=;",
	reflect.TypeOf(VpcTreeNode{}):           "shape=image;aspect=fixed;image=data:image/svg+xml,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iMzNweCIgaGVpZ2h0PSIyOHB4IiB2aWV3Qm94PSIwIDAgMzMgMjgiIHZlcnNpb249IjEuMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI+CiAgICA8IS0tIEdlbmVyYXRvcjogU2tldGNoIDUzICg3MjUyMCkgLSBodHRwczovL3NrZXRjaGFwcC5jb20gLS0+CiAgICA8dGl0bGU+VlBDIEJsYWNrPC90aXRsZT4KICAgIDxkZXNjPkNyZWF0ZWQgd2l0aCBTa2V0Y2guPC9kZXNjPgogICAgPGRlZnM+CiAgICAgICAgPHBvbHlnb24gaWQ9InBhdGgtMSIgcG9pbnRzPSIwIDAuOTk4IDMyIDAuOTk4IDMyIDI0LjAwMDIgMCAyNC4wMDAyIj48L3BvbHlnb24+CiAgICA8L2RlZnM+CiAgICA8ZyBpZD0iUGFnZS0xIiBzdHJva2U9Im5vbmUiIHN0cm9rZS13aWR0aD0iMSIgZmlsbD0ibm9uZSIgZmlsbC1ydWxlPSJldmVub2RkIj4KICAgICAgICA8ZyBpZD0iVlBDLUJsYWNrIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgwLjQ0NDU3MCwgLTAuOTk5ODc1KSI+CiAgICAgICAgICAgIDxwYXRoIGQ9Ik0xMi4wMDEzLDI3LjAwMTggTDEyLjAwMTMsMjEuMDAxOCBMMjAuMDAxMywyMS4wMDE4IEwyMC4wMDIzLDI3LjAwMTggTDEyLjAwMTMsMjcuMDAxOCBaIE0xNC4wMDEzLDE2LjAwMTggQzE0LjAwMTMsMTQuODk3OCAxNC44OTczLDE0LjAwMTggMTYuMDAxMywxNC4wMDE4IEMxNy4xMDUzLDE0LjAwMTggMTguMDAxMywxNC44OTc4IDE4LjAwMTMsMTYuMDAxOCBMMTguMDAxMywxOS4wMDE4IEwxNC4wMDEzLDE5LjAwMTggTDE0LjAwMTMsMTYuMDAxOCBaIE0yMC4wMDEzLDE5LjAwMTggTDIwLjAwMTMsMTYuMDAxOCBDMjAuMDAxMywxMy43OTI4IDE4LjIxMDMsMTIuMDAxOCAxNi4wMDEzLDEyLjAwMTggQzEzLjc5MjMsMTIuMDAxOCAxMi4wMDEzLDEzLjc5MjggMTIuMDAxMywxNi4wMDE4IEwxMi4wMDEzLDE5LjAwMTggQzEwLjg5NzMsMTkuMDAyOCAxMC4wMDIzLDE5Ljg5NzggMTAuMDAxMywyMS4wMDE4IEwxMC4wMDEzLDI3LjAwMTggQzEwLjAwMjMsMjguMTA1OCAxMC44OTczLDI5LjAwMDggMTIuMDAxMywyOS4wMDE4IEwyMC4wMDEzLDI5LjAwMTggQzIxLjEwNTMsMjkuMDAwOCAyMi4wMDAzLDI4LjEwNTggMjIuMDAxMywyNy4wMDE4IEwyMi4wMDEzLDIxLjAwMTggQzIyLjAwMDMsMTkuODk3OCAyMS4xMDUzLDE5LjAwMjggMjAuMDAxMywxOS4wMDE4IEwyMC4wMDEzLDE5LjAwMTggWiIgaWQ9IkZpbGwtMSIgZmlsbD0iIzAwMDAwMCI+PC9wYXRoPgogICAgICAgICAgICA8ZyBpZD0iR3JvdXAtNSIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMC4wMDAwMDAsIDAuMDAxODAwKSI+CiAgICAgICAgICAgICAgICA8bWFzayBpZD0ibWFzay0yIiBmaWxsPSJ3aGl0ZSI+CiAgICAgICAgICAgICAgICAgICAgPHVzZSB4bGluazpocmVmPSIjcGF0aC0xIj48L3VzZT4KICAgICAgICAgICAgICAgIDwvbWFzaz4KICAgICAgICAgICAgICAgIDxnIGlkPSJDbGlwLTQiPjwvZz4KICAgICAgICAgICAgICAgIDxwYXRoIGQ9Ik0yNS44MzA0LDkuMTE1MiBDMjUuMDU2NCw1LjA5NTIgMjEuOTExNCwxLjk1MzIgMTcuODkxNCwxLjE4MTIgQzEyLjQ2NzQsMC4xMzQyIDcuMjIxNCwzLjY4MTIgNi4xNzM0LDkuMTA1MiBDNi4xNzI0LDkuMTA4MiA2LjE3MTQsOS4xMTIyIDYuMTcxNCw5LjExNTIgQzIuMDk0NCw5Ljg1MDIgLTAuNjE1NiwxMy43NTIyIDAuMTIwNCwxNy44MzAyIEMwLjc2NDQsMjEuMzk3MiAzLjg2NzQsMjMuOTk1MiA3LjQ5MjQsMjQuMDAwMiBMOC4wMDE0LDI0LjAwMDIgTDguMDAxNCwyMi4wMDAyIEw3LjQ5NjQsMjIuMDAwMiBDNC40NTc0LDIxLjk5NjIgMS45OTc0LDE5LjUzMDIgMi4wMDE0LDE2LjQ5MTIgQzIuMDA0NCwxMy44MzIyIDMuOTEwNCwxMS41NTUyIDYuNTI3NCwxMS4wODMyIEw3Ljg3NTQsMTAuODM5MiBMOC4xMzU0LDkuNDkzMiBDOC45NzQ0LDUuMTQ5MiAxMy4xNzU0LDIuMzA4MiAxNy41MTk0LDMuMTQ3MiBDMjAuNzMyNCwzLjc2NzIgMjMuMjQ1NCw2LjI4MDIgMjMuODY2NCw5LjQ5MzIgTDI0LjEyNTQsMTAuODM5MiBMMjUuNDc0NCwxMS4wODMyIEMyOC40NjQ0LDExLjYyMjIgMzAuNDUxNCwxNC40ODQyIDI5LjkxMjQsMTcuNDc0MiBDMjkuNDQwNCwyMC4wOTAyIDI3LjE2NzQsMjEuOTk1MiAyNC41MDk0LDIyLjAwMDIgTDI0LjAwMTQsMjIuMDAwMiBMMjQuMDAxNCwyNC4wMDAyIEwyNC41MDk0LDI0LjAwMDIgQzI4LjY1MTQsMjMuOTk0MiAzMi4wMDY0LDIwLjYzMTIgMzIuMDAwNCwxNi40ODcyIEMzMS45OTQ0LDEyLjg2MjIgMjkuMzk3NCw5Ljc1OTIgMjUuODMwNCw5LjExNTIiIGlkPSJGaWxsLTMiIGZpbGw9IiMwMDAwMDAiIG1hc2s9InVybCgjbWFzay0yKSI+PC9wYXRoPgogICAgICAgICAgICA8L2c+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4=;",
	reflect.TypeOf(ZoneTreeNode{}):          "shape=image;aspect=fixed;image=data:image/svg+xml,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iMjlweCIgaGVpZ2h0PSIyNnB4IiB2aWV3Qm94PSIwIDAgMjkgMjYiIHZlcnNpb249IjEuMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI+CiAgICA8IS0tIEdlbmVyYXRvcjogU2tldGNoIDUzICg3MjUyMCkgLSBodHRwczovL3NrZXRjaGFwcC5jb20gLS0+CiAgICA8dGl0bGU+Wm9uZSBCbGFjazwvdGl0bGU+CiAgICA8ZGVzYz5DcmVhdGVkIHdpdGggU2tldGNoLjwvZGVzYz4KICAgIDxnIGlkPSJQYWdlLTEiIHN0cm9rZT0ibm9uZSIgc3Ryb2tlLXdpZHRoPSIxIiBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPgogICAgICAgIDxnIGlkPSJab25lLUJsYWNrIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgwLjEyNTAwMCwgMC4wMDAwMDApIiBmaWxsPSIjMDAwMDAwIj4KICAgICAgICAgICAgPGcgaWQ9Ikdyb3VwLTMiPgogICAgICAgICAgICAgICAgPHBhdGggZD0iTTI2LjAwMDEsMjQuMDAwMSBMMjEuMDAwMSwyNC4wMDAxIEwyMS4wMDAxLDIwLjAwMDEgTDIzLjAwMDEsMjAuMDAwMSBMMjMuMDAwMSwxOC4wMDAxIEwyMS4wMDAxLDE4LjAwMDEgTDIxLjAwMDEsMTYuMDAwMSBMMjMuMDAwMSwxNi4wMDAxIEwyMy4wMDAxLDE0LjAwMDEgTDIxLjAwMDEsMTQuMDAwMSBMMjEuMDAwMSwxMi4wMDAxIEwyMy4wMDAxLDEyLjAwMDEgTDIzLjAwMDEsMTAuMDAwMSBMMjEuMDAwMSwxMC4wMDAxIEwyMS4wMDAxLDguMDAwMSBMMjYuMDAwMSw4LjAwMDEgTDI2LjAwMDEsMjQuMDAwMSBaIE05LjAwMDEsMjQuMDAwMSBMMTkuMDAwMSwyNC4wMDAxIEwxOS4wMDAxLDIuMDAwMSBMOS4wMDAxLDIuMDAwMSBMOS4wMDAxLDI0LjAwMDEgWiBNMi4wMDAxLDI0LjAwMDEgTDIuMDAwMSw4LjAwMDEgTDcuMDAwMSw4LjAwMDEgTDcuMDAwMSwxMC4wMDAxIEw1LjAwMDEsMTAuMDAwMSBMNS4wMDAxLDEyLjAwMDEgTDcuMDAwMSwxMi4wMDAxIEw3LjAwMDEsMTQuMDAwMSBMNS4wMDAxLDE0LjAwMDEgTDUuMDAwMSwxNi4wMDAxIEw3LjAwMDEsMTYuMDAwMSBMNy4wMDAxLDE4LjAwMDEgTDUuMDAwMSwxOC4wMDAxIEw1LjAwMDEsMjAuMDAwMSBMNy4wMDAxLDIwLjAwMDEgTDcuMDAwMSwyNC4wMDAxIEwyLjAwMDEsMjQuMDAwMSBaIE0yNi4wMDAxLDYuMDAwMSBMMjEuMDAwMSw2LjAwMDEgTDIxLjAwMDEsMi4wMDAxIEMyMC45OTkxLDAuODk2MSAyMC4xMDQxLDAuMDAxMSAxOS4wMDAxLDAuMDAwMSBMOS4wMDAxLDAuMDAwMSBDNy44OTYxLDAuMDAxMSA3LjAwMTEsMC44OTYxIDcuMDAwMSwyLjAwMDEgTDcuMDAwMSw2LjAwMDEgTDIuMDAwMSw2LjAwMDEgQzAuODk2MSw2LjAwMTEgMC4wMDExLDYuODk2MSAwLjAwMDEsOC4wMDAxIEwwLjAwMDEsMjQuMDAwMSBDMC4wMDExLDI1LjEwNDEgMC44OTYxLDI1Ljk5OTEgMi4wMDAxLDI2LjAwMDEgTDI2LjAwMDEsMjYuMDAwMSBDMjcuMTA0MSwyNS45OTkxIDI3Ljk5OTEsMjUuMTA0MSAyOC4wMDAxLDI0LjAwMDEgTDI4LjAwMDEsOC4wMDAxIEMyNy45OTkxLDYuODk2MSAyNy4xMDQxLDYuMDAxMSAyNi4wMDAxLDYuMDAwMSBMMjYuMDAwMSw2LjAwMDEgWiIgaWQ9IkZpbGwtMSI+PC9wYXRoPgogICAgICAgICAgICA8L2c+CiAgICAgICAgICAgIDxwb2x5Z29uIGlkPSJGaWxsLTQiIHBvaW50cz0iMTIgNiAxNiA2IDE2IDQgMTIgNCI+PC9wb2x5Z29uPgogICAgICAgICAgICA8cG9seWdvbiBpZD0iRmlsbC02IiBwb2ludHM9IjEyIDEwIDE2IDEwIDE2IDggMTIgOCI+PC9wb2x5Z29uPgogICAgICAgICAgICA8cG9seWdvbiBpZD0iRmlsbC03IiBwb2ludHM9IjEyIDE0IDE2IDE0IDE2IDEyIDEyIDEyIj48L3BvbHlnb24+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4=;",
	reflect.TypeOf(PartialSGTreeNode{}):     "shape=image;aspect=fixed;image=data:image/svg+xml,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iMjhweCIgaGVpZ2h0PSIyOHB4IiB2aWV3Qm94PSIwIDAgMjggMjgiIHZlcnNpb249IjEuMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI+CiAgICA8IS0tIEdlbmVyYXRvcjogU2tldGNoIDUzICg3MjUyMCkgLSBodHRwczovL3NrZXRjaGFwcC5jb20gLS0+CiAgICA8dGl0bGU+U2VjdXJpdHkgR3JvdXAgQmxhY2s8L3RpdGxlPgogICAgPGRlc2M+Q3JlYXRlZCB3aXRoIFNrZXRjaC48L2Rlc2M+CiAgICA8ZGVmcz4KICAgICAgICA8cG9seWdvbiBpZD0icGF0aC0xIiBwb2ludHM9IjAgMC4wMDA0IDI0IDAuMDAwNCAyNCAyOCAwIDI4Ij48L3BvbHlnb24+CiAgICA8L2RlZnM+CiAgICA8ZyBpZD0iUGFnZS0xIiBzdHJva2U9Im5vbmUiIHN0cm9rZS13aWR0aD0iMSIgZmlsbD0ibm9uZSIgZmlsbC1ydWxlPSJldmVub2RkIj4KICAgICAgICA8ZyBpZD0iU2VjdXJpdHktR3JvdXAtQmxhY2siPgogICAgICAgICAgICA8cGF0aCBkPSJNOSwxOSBMNywxOSBMNywxNyBDNy4wMDIsMTUuMzQ0IDguMzQ0LDE0LjAwMiAxMCwxNCBMMTYsMTQgTDE2LDE2IEwxMCwxNiBDOS40NDgsMTYgOS4wMDEsMTYuNDQ4IDksMTcgTDksMTkgWiIgaWQ9IkZpbGwtMSIgZmlsbD0iIzAwMDAwMCI+PC9wYXRoPgogICAgICAgICAgICA8cGF0aCBkPSJNMTMsNyBDMTEuODk2LDcgMTEsNy44OTYgMTEsOSBDMTEsMTAuMTA0IDExLjg5NiwxMSAxMywxMSBDMTQuMTA0LDExIDE1LDEwLjEwNCAxNSw5IEMxNC45OTksNy44OTYgMTQuMTA0LDcuMDAxIDEzLDcgTTEzLDEzIEMxMC43OTEsMTMgOSwxMS4yMDkgOSw5IEM5LDYuNzkxIDEwLjc5MSw1IDEzLDUgQzE1LjIwOSw1IDE3LDYuNzkxIDE3LDkgQzE2Ljk5NywxMS4yMDggMTUuMjA4LDEyLjk5OCAxMywxMyIgaWQ9IkZpbGwtMyIgZmlsbD0iIzAwMDAwMCI+PC9wYXRoPgogICAgICAgICAgICA8cGF0aCBkPSJNMjIsMTQgQzIwLjg5NiwxNCAyMCwxNC44OTYgMjAsMTYgQzIwLDE3LjEwNCAyMC44OTYsMTggMjIsMTggQzIzLjEwNCwxOCAyNCwxNy4xMDQgMjQsMTYgQzIzLjk5OSwxNC44OTYgMjMuMTA0LDE0LjAwMSAyMiwxNCBNMjIsMjAgQzE5Ljc5MSwyMCAxOCwxOC4yMDkgMTgsMTYgQzE4LDEzLjc5MSAxOS43OTEsMTIgMjIsMTIgQzI0LjIwOSwxMiAyNiwxMy43OTEgMjYsMTYgQzI1Ljk5NywxOC4yMDggMjQuMjA4LDE5Ljk5OCAyMiwyMCIgaWQ9IkZpbGwtNSIgZmlsbD0iIzAwMDAwMCI+PC9wYXRoPgogICAgICAgICAgICA8cGF0aCBkPSJNMjgsMjYgTDI2LDI2IEwyNiwyNCBDMjUuOTk5LDIzLjQ0OCAyNS41NTIsMjMgMjUsMjMgTDE5LDIzIEMxOC40NDgsMjMgMTguMDAxLDIzLjQ0OCAxOCwyNCBMMTgsMjYgTDE2LDI2IEwxNiwyNCBDMTYuMDAyLDIyLjM0NCAxNy4zNDQsMjEuMDAyIDE5LDIxIEwyNSwyMSBDMjYuNjU2LDIxLjAwMiAyNy45OTgsMjIuMzQ0IDI4LDI0IEwyOCwyNiBaIiBpZD0iRmlsbC03IiBmaWxsPSIjMDAwMDAwIj48L3BhdGg+CiAgICAgICAgICAgIDxnIGlkPSJHcm91cC0xMSI+CiAgICAgICAgICAgICAgICA8bWFzayBpZD0ibWFzay0yIiBmaWxsPSJ3aGl0ZSI+CiAgICAgICAgICAgICAgICAgICAgPHVzZSB4bGluazpocmVmPSIjcGF0aC0xIj48L3VzZT4KICAgICAgICAgICAgICAgIDwvbWFzaz4KICAgICAgICAgICAgICAgIDxnIGlkPSJDbGlwLTEwIj48L2c+CiAgICAgICAgICAgICAgICA8cGF0aCBkPSJNMTIsMjUuNzMzNCBMNi43NjYsMjIuOTQyNCBDMy44MywyMS4zODA0IDEuOTk2LDE4LjMyNTQgMiwxNS4wMDA0IEwyLDIuMDAwNCBMMjIsMi4wMDA0IEwyMiw4LjAwMDQgTDI0LDguMDAwNCBMMjQsMi4wMDA0IEMyMy45OTksMC44OTY0IDIzLjEwNCwwLjAwMTQgMjIsMC4wMDA0IEwyLDAuMDAwNCBDMC44OTYsMC4wMDE0IDAuMDAxLDAuODk2NCAwLDIuMDAwNCBMMCwxNS4wMDA0IEMtMC4wMDUsMTkuMDY0NCAyLjIzNiwyMi43OTg0IDUuODI0LDI0LjcwNzQgTDEyLDI4LjAwMDQgTDEyLDI1LjczMzQgWiIgaWQ9IkZpbGwtOSIgZmlsbD0iIzAwMDAwMCIgbWFzaz0idXJsKCNtYXNrLTIpIj48L3BhdGg+CiAgICAgICAgICAgIDwvZz4KICAgICAgICA8L2c+CiAgICA8L2c+Cjwvc3ZnPg==;",
	reflect.TypeOf(SubnetTreeNode{}):        "shape=image;aspect=fixed;image=data:image/svg+xml,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iMjlweCIgaGVpZ2h0PSIyOXB4IiB2aWV3Qm94PSIwIDAgMjkgMjkiIHZlcnNpb249IjEuMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI+CiAgICA8IS0tIEdlbmVyYXRvcjogU2tldGNoIDUzICg3MjUyMCkgLSBodHRwczovL3NrZXRjaGFwcC5jb20gLS0+CiAgICA8dGl0bGU+SUJNIFN1Ym5ldCA6IEFDTCBCbGFjazwvdGl0bGU+CiAgICA8ZGVzYz5DcmVhdGVkIHdpdGggU2tldGNoLjwvZGVzYz4KICAgIDxnIGlkPSJQYWdlLTEiIHN0cm9rZT0ibm9uZSIgc3Ryb2tlLXdpZHRoPSIxIiBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPgogICAgICAgIDxnIGlkPSJJQk0tU3VibmV0LTotQUNMLUJsYWNrIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgwLjc1MDAwMCwgMC4wNzQ5NTkpIiBmaWxsPSIjMDAwMDAwIj4KICAgICAgICAgICAgPHBhdGggZD0iTTI0LjAxNjEsMjYuMjIyMSBDMjIuOTEyMSwyNi4yMjIxIDIyLjAxNjEsMjUuMzI2MSAyMi4wMTYxLDI0LjIyMjEgQzIyLjAxNjEsMjMuMTE4MSAyMi45MTIxLDIyLjIyMjEgMjQuMDE2MSwyMi4yMjIxIEMyNS4xMjAxLDIyLjIyMjEgMjYuMDE2MSwyMy4xMTgxIDI2LjAxNjEsMjQuMjIyMSBDMjYuMDEzMSwyNS4zMjUxIDI1LjExOTEsMjYuMjE5MSAyNC4wMTYxLDI2LjIyMjEgTTQuMDE2MSwyNi4yMjIxIEMyLjkxMjEsMjYuMjIyMSAyLjAxNjEsMjUuMzI2MSAyLjAxNjEsMjQuMjIyMSBDMi4wMTYxLDIzLjExODEgMi45MTIxLDIyLjIyMjEgNC4wMTYxLDIyLjIyMjEgQzUuMTIwMSwyMi4yMjIxIDYuMDE2MSwyMy4xMTgxIDYuMDE2MSwyNC4yMjIxIEM2LjAxMzEsMjUuMzI1MSA1LjExOTEsMjYuMjE5MSA0LjAxNjEsMjYuMjIyMSBNNC4wMTYxLDYuMjIyMSBDMi45MTIxLDYuMjIyMSAyLjAxNjEsNS4zMjYxIDIuMDE2MSw0LjIyMjEgQzIuMDE2MSwzLjExODEgMi45MTIxLDIuMjIyMSA0LjAxNjEsMi4yMjIxIEM1LjEyMDEsMi4yMjIxIDYuMDE2MSwzLjExODEgNi4wMTYxLDQuMjIyMSBDNi4wMTMxLDUuMzI1MSA1LjExOTEsNi4yMTkxIDQuMDE2MSw2LjIyMjEgTTI0LjAxNjEsMi4yMjIxIEMyNS4xMjAxLDIuMjIyMSAyNi4wMTYxLDMuMTE4MSAyNi4wMTYxLDQuMjIyMSBDMjYuMDE2MSw1LjMyNjEgMjUuMTIwMSw2LjIyMjEgMjQuMDE2MSw2LjIyMjEgQzIyLjkxMjEsNi4yMjIxIDIyLjAxNjEsNS4zMjYxIDIyLjAxNjEsNC4yMjIxIEMyMi4wMTkxLDMuMTE4MSAyMi45MTMxLDIuMjI1MSAyNC4wMTYxLDIuMjIyMSBNMjQuMDE2MSwyMC4wMDAxIEMyMy4zMDUxLDE5Ljk5ODEgMjIuNjA5MSwyMC4yMDcxIDIyLjAxNjEsMjAuNjAwMSBMMTcuNDMwMSwxNi4wMDAxIEwxNi4wMTYxLDE3LjQxNDEgTDIwLjYxNjEsMjIuMDAwMSBDMjAuNDQwMSwyMi4zMTQxIDIwLjMwNjEsMjIuNjUxMSAyMC4yMTYxLDIzLjAwMDEgTDcuODc0MSwyMy4wMDAxIEM3Ljc3NDEsMjIuNjQ1MSA3LjYyMDEsMjIuMzA3MSA3LjQxNjEsMjIuMDAwMSBMMjIuMDE2MSw3LjQwMDEgQzIzLjgwNzEsOC41ODYxIDI2LjUzNzEsOC4wOTQxIDI3Ljc5NDEsNS4xOTgxIEMyNy45MTAxLDQuOTMyMSAyNy45OTIxLDQuNjQ0MSAyOC4wMTYxLDQuMzU1MSBDMjguMjIxMSwxLjk5NDEgMjYuMzcwMSwwLjAwOTEgMjQuMDQ4MSwwLjAwMDEgQzIyLjIxODEsLTAuMDA2OSAyMC42MTcxLDEuMjI4MSAyMC4xNTkxLDMuMDAwMSBMNy45MTYxLDMuMDAwMSBDNy40MzMxLDEuMjQwMSA1Ljg0MTEsMC4wMTUxIDQuMDE2MSwwLjAwMDEgQzEuNjc0MSwwLjAwMDEgLTAuMTk2OSwyLjAxMjEgMC4wMzYxLDQuNDAyMSBDMC4wNjcxLDQuNzIzMSAwLjE2MzEsNS4wNDExIDAuMjk5MSw1LjMzNTEgQzEuNTgyMSw4LjEwOTEgNC4yNTQxLDguNTY3MSA2LjAxNjEsNy40MDAxIEwxMC42MDIxLDEyLjAwMDEgTDEyLjAxNjEsMTAuNTg2MSBMNy40MTYxLDYuMDAwMSBDNy41OTIxLDUuNjg1MSA3LjcyNjEsNS4zNDkxIDcuODE2MSw1LjAwMDEgTDIwLjE1ODEsNS4wMDAxIEMyMC4yNTgxLDUuMzU1MSAyMC40MTIxLDUuNjkyMSAyMC42MTYxLDYuMDAwMSBMNi4wMTYxLDIwLjYwMDEgQzQuMjI0MSwxOS40MTMxIDEuNDk0MSwxOS45MDcxIDAuMjM3MSwyMi44MDUxIEMwLjEyMjEsMjMuMDcwMSAwLjA0MDEsMjMuMzU3MSAwLjAxNjEsMjMuNjQ1MSBDLTAuMTg3OSwyNi4wMDYxIDEuNjYzMSwyNy45OTExIDMuOTg0MSwyOC4wMDAxIEM1LjgxNDEsMjguMDA3MSA3LjQxNTEsMjYuNzcyMSA3Ljg3MzEsMjUuMDAwMSBMMjAuMTE2MSwyNS4wMDAxIEMyMC43MjkxLDI3LjQxMzEgMjMuNDEyMSwyOC43NTUxIDI1Ljc4NzEsMjcuNjEwMSBDMjcuMTAzMSwyNi45NzUxIDI3Ljk4NzEsMjUuNjA0MSAyOC4wMTgxLDI0LjE0MzEgQzI4LjA2ODEsMjEuNzk1MSAyNi4yMTIxLDIwLjAwNjEgMjQuMDE2MSwyMC4wMDAxIiBpZD0iRmlsbC0xIj48L3BhdGg+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4=;",
}
var textStyles = map[reflect.Type]string{
	reflect.TypeOf(PublicNetworkTreeNode{}): "text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;",
	reflect.TypeOf(CloudTreeNode{}):         "text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;",
	reflect.TypeOf(VpcTreeNode{}):           "text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;",
	reflect.TypeOf(ZoneTreeNode{}):          "text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;",
	reflect.TypeOf(SubnetTreeNode{}):        "text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;",
	reflect.TypeOf(PartialSGTreeNode{}):     "text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;",
	reflect.TypeOf(ConnectivityTreeNode{}):  "edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];",
	reflect.TypeOf(VsiLineTreeNode{}):       "edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];",
}

var decoreStyles = map[reflect.Type]string{
	reflect.TypeOf(PublicNetworkTreeNode{}): "rounded=0;whiteSpace=wrap;html=1;strokeColor=none;fillColor=#1192E8;",
	reflect.TypeOf(CloudTreeNode{}):         "rounded=0;whiteSpace=wrap;html=1;strokeColor=none;fillColor=#1192E8;",
	reflect.TypeOf(VpcTreeNode{}):           "rounded=0;whiteSpace=wrap;html=1;strokeColor=none;fillColor=#1192E8;",
	reflect.TypeOf(ZoneTreeNode{}):          "rounded=0;whiteSpace=wrap;html=1;strokeColor=none;fillColor=#878d96;",
	reflect.TypeOf(SubnetTreeNode{}):        "rounded=0;whiteSpace=wrap;html=1;strokeColor=none;fillColor=#1192E8;",
	reflect.TypeOf(PartialSGTreeNode{}):     "rounded=0;whiteSpace=wrap;html=1;strokeColor=none;fillColor=#FA4D56;",
}

func (data *drawioData) Style(tn TreeNodeInterface) string {
	if reflect.TypeOf(tn).Elem() == reflect.TypeOf(ConnectivityTreeNode{}) {
		return connectivityStyle(tn.(*ConnectivityTreeNode))
	} else if reflect.TypeOf(tn).Elem() == reflect.TypeOf(NITreeNode{}) && !data.ShowNIIcon {
		return styles[reflect.TypeOf(VsiTreeNode{})]
	}
	return styles[reflect.TypeOf(tn).Elem()]
}
func (data *drawioData) TextStyle(tn TreeNodeInterface) string {
	return textStyles[reflect.TypeOf(tn).Elem()]
}
func (data *drawioData) TagStyle(tn TreeNodeInterface) string {
	return tagStyles[reflect.TypeOf(tn).Elem()]
}
func (data *drawioData) HasTag(tn TreeNodeInterface) bool {
	_, ok := tagStyles[reflect.TypeOf(tn).Elem()]
	return ok
}
func (data *drawioData) DecoreStyle(tn TreeNodeInterface) string {
	return decoreStyles[reflect.TypeOf(tn).Elem()]
}
func (data *drawioData) ElementComment(tn TreeNodeInterface) string {
	return reflect.TypeOf(tn).Elem().Name() + " " + tn.Label()
}
func (data *drawioData) FIPStyle() string { return fipStyle }
func (data *drawioData) VsiStyle() string { return vsiStyle }
