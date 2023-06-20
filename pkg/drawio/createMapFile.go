package drawio

import (
	_ "embed"
	"os"
	"text/template"
)

//go:embed connectivityMap.drawio.tmpl
var drawioTemplate string

type drawioData struct {
	IconSize   int
	FipXOffset int
	FipYOffset int
	VSIXOffset int
	VSIYOffset int
	VSISize    int
	ShowNIIcon bool
	Nodes      []TreeNodeInterface
}

func (data *drawioData) FIPStyle(tn TreeNodeInterface) string {
	return "shape=image;aspect=fixed;image=data:image/svg+xml,PHN2ZyBpZD0iTGF5ZXJfMSIgZGF0YS1uYW1lPSJMYXllciAxIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OSA0OSI+PGRlZnM+PHN0eWxlPi5jbHMtMXtmaWxsOiMxMTkyZTg7fS5jbHMtMntmaWxsOiNmZmY7fS5jbHMtM3tmaWxsOm5vbmU7fTwvc3R5bGU+PC9kZWZzPjxyZWN0IGNsYXNzPSJjbHMtMSIgeD0iMC41IiB5PSIwLjkyIiB3aWR0aD0iNDgiIGhlaWdodD0iNDcuMTYiIHJ4PSI4Ii8+PHBhdGggY2xhc3M9ImNscy0yIiBkPSJNMzAuMTIsMjEuNDNhMy4xMywzLjEzLDAsMCwwLTMuMDYsMi40NkgyMS45NGEzLjA3LDMuMDcsMCwxLDAsMCwxLjIyaDUuMTJhMy4xMiwzLjEyLDAsMSwwLDMuMDYtMy42OFptMCw0LjkxQTEuODQsMS44NCwwLDEsMSwzMiwyNC41LDEuODUsMS44NSwwLDAsMSwzMC4xMiwyNi4zNFoiLz48cmVjdCBjbGFzcz0iY2xzLTMiIHg9IjE0LjUiIHk9IjE0LjY3IiB3aWR0aD0iMjAiIGhlaWdodD0iMTkuNjUiLz48L3N2Zz4=;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;labelPosition=center;verticalLabelPosition=bottom;align=center;verticalAlign=top;spacingTop=-7;"
}
func (data *drawioData) Style(tn TreeNodeInterface) string {
	switch {
	case tn.IsVSI():
		return "shape=image;aspect=fixed;image=data:image/svg+xml,PHN2ZyBpZD0iTGF5ZXJfMSIgZGF0YS1uYW1lPSJMYXllciAxIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OSA0OSI+PGRlZnM+PHN0eWxlPi5jbHMtMXtmaWxsOiMxOTgwMzg7fS5jbHMtMntmaWxsOiNmZmY7fS5jbHMtM3tmaWxsOm5vbmU7fTwvc3R5bGU+PC9kZWZzPjxyZWN0IGNsYXNzPSJjbHMtMSIgeD0iMC41IiB5PSIwLjUiIHdpZHRoPSI0OCIgaGVpZ2h0PSI0OCIvPjxjaXJjbGUgY2xhc3M9ImNscy0yIiBjeD0iMTguODgiIGN5PSIyOC44OCIgcj0iMC42MyIvPjxyZWN0IGNsYXNzPSJjbHMtMiIgeD0iMTUuNzUiIHk9IjE4LjI1IiB3aWR0aD0iMi41IiBoZWlnaHQ9IjEuMjUiLz48cmVjdCBjbGFzcz0iY2xzLTIiIHg9IjE5LjUiIHk9IjE4LjI1IiB3aWR0aD0iMi41IiBoZWlnaHQ9IjEuMjUiLz48cmVjdCBjbGFzcz0iY2xzLTIiIHg9IjIzLjI1IiB5PSIxOC4yNSIgd2lkdGg9IjIuNSIgaGVpZ2h0PSIxLjI1Ii8+PHJlY3QgY2xhc3M9ImNscy0yIiB4PSIyNyIgeT0iMTguMjUiIHdpZHRoPSIyLjUiIGhlaWdodD0iMS4yNSIvPjxyZWN0IGNsYXNzPSJjbHMtMiIgeD0iMzAuNzUiIHk9IjE4LjI1IiB3aWR0aD0iMi41IiBoZWlnaHQ9IjEuMjUiLz48cGF0aCBjbGFzcz0iY2xzLTIiIGQ9Ik0zMiwzMkgxN2ExLjI1LDEuMjUsMCwwLDEtMS4yNS0xLjI1VjI3QTEuMjUsMS4yNSwwLDAsMSwxNywyNS43NUgzMkExLjI1LDEuMjUsMCwwLDEsMzMuMjUsMjd2My43NUExLjI1LDEuMjUsMCwwLDEsMzIsMzJaTTE3LDI3djMuNzVIMzJWMjdaIi8+PHJlY3QgY2xhc3M9ImNscy0zIiB4PSIxNC41IiB5PSIxNC41IiB3aWR0aD0iMjAiIGhlaWdodD0iMjAiLz48cmVjdCBjbGFzcz0iY2xzLTIiIHg9IjE1Ljc1IiB5PSIyMiIgd2lkdGg9IjE3LjUiIGhlaWdodD0iMS4yNSIvPjwvc3ZnPg==;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;spacingTop=-7;labelPosition=center;verticalLabelPosition=bottom;align=center;verticalAlign=top;"
	case tn.IsUser():
		return "shape=image;aspect=fixed;image=data:image/svg+xml,PHN2ZyBpZD0iTGF5ZXJfMSIgZGF0YS1uYW1lPSJMYXllciAxIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OSA0OSI+PGRlZnM+PHN0eWxlPi5jbHMtMXtmaWxsOm5vbmU7fS5jbHMtMntmaWxsOiNmZmY7ZmlsbC1ydWxlOmV2ZW5vZGQ7fTwvc3R5bGU+PC9kZWZzPjxyZWN0IHg9IjAuNSIgeT0iMC41IiB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHJ4PSIyNCIvPjxyZWN0IGNsYXNzPSJjbHMtMSIgeD0iMTQuNSIgeT0iMTQuNSIgd2lkdGg9IjIwIiBoZWlnaHQ9IjIwIi8+PHBhdGggaWQ9IkZpbGwtMyIgY2xhc3M9ImNscy0yIiBkPSJNMzAuOCwzMy44N0gyOVYyOS41OUEyLjYzLDIuNjMsMCwwLDAsMjYuMywyN0gyMi43QTIuNjMsMi42MywwLDAsMCwyMCwyOS41OXY0LjI4SDE4LjJWMjkuNTlhNC40MSw0LjQxLDAsMCwxLDQuNS00LjI4aDMuNmE0LjQxLDQuNDEsMCwwLDEsNC41LDQuMjhaIi8+PHBhdGggaWQ9IkZpbGwtNSIgY2xhc3M9ImNscy0yIiBkPSJNMjQuNSwxNS4wNUE0LjM5LDQuMzksMCwwLDAsMjAsMTkuMzNhNC41MSw0LjUxLDAsMCwwLDksMCw0LjM5LDQuMzksMCwwLDAtNC41LTQuMjhtMCwxLjcxYTIuNTcsMi41NywwLDEsMS0yLjcsMi41NywyLjY0LDIuNjQsMCwwLDEsMi43LTIuNTciLz48L3N2Zz4=;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;labelPosition=center;verticalLabelPosition=bottom;align=center;verticalAlign=top;spacingTop=-7;"
	case tn.IsGateway():
		return "shape=image;aspect=fixed;image=data:image/svg+xml,PHN2ZyBpZD0iTGF5ZXJfMSIgZGF0YS1uYW1lPSJMYXllciAxIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OSA0OSI+PGRlZnM+PHN0eWxlPi5jbHMtMXtmaWxsOiMxMTkyZTg7fS5jbHMtMntmaWxsOiNmZmY7fS5jbHMtM3tmaWxsOm5vbmU7fTwvc3R5bGU+PC9kZWZzPjxyZWN0IGNsYXNzPSJjbHMtMSIgeD0iMC41IiB5PSIwLjUiIHdpZHRoPSI0OCIgaGVpZ2h0PSI0OCIgcng9IjgiLz48cGF0aCBjbGFzcz0iY2xzLTIiIGQ9Ik0zMy41MSwyNS4zOGExLjIzLDEuMjMsMCwwLDAsMC0xLjc2TDI5Ljg5LDIwbDEuODEtMS43OWExLjI1LDEuMjUsMCwxLDAtLjU4LTIuMDksMS4yMiwxLjIyLDAsMCwwLS4zMiwxLjIyTDI5LDE5LjEybC0zLjYzLTMuNjNhMS4yMywxLjIzLDAsMCwwLTEuNzYsMEwyMCwxOS4xMWwtMS43OS0xLjgyYTEuMjQsMS4yNCwwLDEsMC0yLjA5LjU5LDEuMjIsMS4yMiwwLDAsMCwxLjIyLjMyTDE5LjEyLDIwbC0zLjYzLDMuNjNhMS4yMywxLjIzLDAsMCwwLDAsMS43NkwxOS4xMiwyOSwxNy4zNCwzMC44YTEuMjIsMS4yMiwwLDAsMC0xLjIyLjMyLDEuMjQsMS4yNCwwLDEsMCwyLjA5LjU5TDIwLDI5Ljg5bDMuNjIsMy42MmExLjIzLDEuMjMsMCwwLDAsMS43NiwwTDI5LDI5Ljg4bDEuNzksMS43OGExLjIyLDEuMjIsMCwwLDAsLjMyLDEuMjIsMS4yNCwxLjI0LDAsMSwwLC41OC0yLjA5TDI5Ljg5LDI5Wm0tOSw3LjI0TDE2LjM4LDI0LjVsOC4xMi04LjEyLDguMTIsOC4xMloiLz48cmVjdCBjbGFzcz0iY2xzLTMiIHg9IjE0LjUiIHk9IjE0LjUiIHdpZHRoPSIyMCIgaGVpZ2h0PSIyMCIvPjxwYXRoIGNsYXNzPSJjbHMtMiIgZD0iTTI2LjM4LDIzLjI1SDIzLjI1VjIyYTEuMjUsMS4yNSwwLDAsMSwyLjUsMEgyN2EyLjUsMi41LDAsMCwwLTUsMHYxLjQyYTEuMjYsMS4yNiwwLDAsMC0uNjIsMS4wOHYzLjEyYTEuMjYsMS4yNiwwLDAsMCwxLjI0LDEuMjZoMy43NmExLjI2LDEuMjYsMCwwLDAsMS4yNC0xLjI2VjI0LjVBMS4yNSwxLjI1LDAsMCwwLDI2LjM4LDIzLjI1Wm0wLDQuMzdIMjIuNjJWMjQuNWgzLjc2WiIvPjwvc3ZnPg==;fontSize=14;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;spacingTop=-7;labelPosition=center;verticalLabelPosition=bottom;align=center;verticalAlign=top;"
	case tn.IsInternet():
		return "shape=image;aspect=fixed;image=data:image/svg+xml,PHN2ZyBpZD0iTGF5ZXJfMSIgZGF0YS1uYW1lPSJMYXllciAxIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OSA0OSI+PGRlZnM+PHN0eWxlPi5jbHMtMXtmaWxsOiMxMTkyZTg7fS5jbHMtMntmaWxsOiNmZmY7fS5jbHMtM3tmaWxsOm5vbmU7fTwvc3R5bGU+PC9kZWZzPjxyZWN0IGNsYXNzPSJjbHMtMSIgeD0iMC41IiB5PSIwLjUiIHdpZHRoPSI0OCIgaGVpZ2h0PSI0OCIgcng9IjgiLz48cGF0aCBjbGFzcz0iY2xzLTIiIGQ9Ik0yNC41LDE1Ljc1YTguNzUsOC43NSwwLDEsMCw4Ljc1LDguNzVBOC43NSw4Ljc1LDAsMCwwLDI0LjUsMTUuNzVaTTMyLDIzLjg4SDI4LjI1YTE1LjE5LDE1LjE5LDAsMCwwLTEuNzQtNi42QTcuNSw3LjUsMCwwLDEsMzIsMjMuODhaTTI0LjUsMzJoLS40MkExMy43MiwxMy43MiwwLDAsMSwyMiwyNS4xMmg1QTEzLjYzLDEzLjYzLDAsMCwxLDI0Ljk0LDMyWk0yMiwyMy44OEExMy42MywxMy42MywwLDAsMSwyNC4wNiwxN2EzLjkzLDMuOTMsMCwwLDEsLjg0LDBBMTMuNjQsMTMuNjQsMCwwLDEsMjcsMjMuODhabS40OC02LjZhMTUuMTgsMTUuMTgsMCwwLDAtMS43Myw2LjZIMTdhNy41LDcuNSwwLDAsMSw1LjQ5LTYuNlpNMTcsMjUuMTJoMy43NWExNS4yLDE1LjIsMCwwLDAsMS43Miw2LjZBNy41Miw3LjUyLDAsMCwxLDE3LDI1LjEyWm05LjQ4LDYuNmExNS4xOSwxNS4xOSwwLDAsMCwxLjc0LTYuNkgzMkE3LjUsNy41LDAsMCwxLDI2LjUxLDMxLjcyWiIvPjxyZWN0IGlkPSJfVHJhbnNwYXJlbnRfUmVjdGFuZ2xlXyIgZGF0YS1uYW1lPSIgVHJhbnNwYXJlbnQgUmVjdGFuZ2xlICIgY2xhc3M9ImNscy0zIiB4PSIxNC41IiB5PSIxNC41IiB3aWR0aD0iMjAiIGhlaWdodD0iMjAiLz48L3N2Zz4=;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;fontSize=14;labelPosition=center;verticalLabelPosition=bottom;align=center;verticalAlign=top;spacingTop=-7;"
	case tn.IsInternetService():
		return "shape=image;aspect=fixed;image=data:image/svg+xml,PHN2ZyBpZD0iTGF5ZXJfMSIgZGF0YS1uYW1lPSJMYXllciAxIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OSA0OSI+PGRlZnM+PHN0eWxlPi5jbHMtMXtmaWxsOiMxMTkyZTg7fS5jbHMtMntmaWxsOiNmZmY7fS5jbHMtM3tmaWxsOm5vbmU7fTwvc3R5bGU+PC9kZWZzPjxyZWN0IGNsYXNzPSJjbHMtMSIgeD0iMC41IiB5PSIwLjUiIHdpZHRoPSI0OCIgaGVpZ2h0PSI0OCIvPjxwYXRoIGNsYXNzPSJjbHMtMiIgZD0iTTMxLjg3LDIwLjc1YTYuMjUsNi4yNSwwLDAsMC0xMi4yNi4wOCw0LjY4LDQuNjgsMCwwLDAsLjgzLDkuMjloLjk0VjI4Ljg3aC0uOTRBMy40MywzLjQzLDAsMCwxLDIwLjIsMjJsLjUyLDAsLjA2LS41MmE1LDUsMCwwLDEsOS44MS0uNzFaIi8+PHJlY3QgY2xhc3M9ImNscy0zIiB4PSIxNC41IiB5PSIxNC41IiB3aWR0aD0iMjAiIGhlaWdodD0iMjAiLz48cGF0aCBjbGFzcz0iY2xzLTIiIGQ9Ik0zMS4zNywyOS41YTEuODQsMS44NCwwLDAsMC0xLjIuNDVsLTIuNTYtMS41NGMwLS4wNSwwLS4xLDAtLjE2czAtLjExLDAtLjE2bDIuNTYtMS41NGExLjg2LDEuODYsMCwwLDAsMS4yLjQ1LDEuODgsMS44OCwwLDEsMC0xLjg3LTEuODgsMS40MiwxLjQyLDAsMCwwLDAsLjM2bC0yLjQ1LDEuNDZhMS44NiwxLjg2LDAsMCwwLTEuMzQtLjU3LDEuODgsMS44OCwwLDAsMCwwLDMuNzUsMS44NSwxLjg1LDAsMCwwLDEuMzQtLjU2TDI5LjU0LDMxYTEuNDUsMS40NSwwLDAsMCwwLC4zNSwxLjg4LDEuODgsMCwxLDAsMS44Ny0xLjg3Wm0wLTVhLjYzLjYzLDAsMSwxLS42Mi42MkEuNjMuNjMsMCwwLDEsMzEuMzcsMjQuNVptLTUuNjIsNC4zN2EuNjMuNjMsMCwwLDEtLjYzLS42Mi42NC42NCwwLDAsMSwuNjMtLjYzLjYzLjYzLDAsMCwxLC42Mi42M0EuNjIuNjIsMCwwLDEsMjUuNzUsMjguODdaTTMxLjM3LDMyYS42My42MywwLDEsMSwuNjMtLjYzQS42My42MywwLDAsMSwzMS4zNywzMloiLz48L3N2Zz4=;fontSize=14;labelPosition=center;verticalLabelPosition=bottom;align=center;verticalAlign=top;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;spacingTop=-6;"
	case tn.IsEndpoint():
		return "shape=image;aspect=fixed;image=data:image/svg+xml,PHN2ZyBpZD0iTGF5ZXJfMSIgZGF0YS1uYW1lPSJMYXllciAxIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OSA0OSI+PGRlZnM+PHN0eWxlPi5jbHMtMXtmaWxsOiMxMTkyZTg7fS5jbHMtMntmaWxsOiNmZmY7fS5jbHMtM3tmaWxsOm5vbmU7fTwvc3R5bGU+PC9kZWZzPjxyZWN0IGNsYXNzPSJjbHMtMSIgeD0iMC41IiB5PSIwLjUiIHdpZHRoPSI0OCIgaGVpZ2h0PSI0OCIvPjxwYXRoIGlkPSJ2cGNfZ3JhZGllbnRfYm90dG9tIiBkYXRhLW5hbWU9InZwYyBncmFkaWVudCBib3R0b20iIGNsYXNzPSJjbHMtMiIgZD0iTTI3LDMxLjM4SDE4Ljg4YTEuMjcsMS4yNywwLDAsMS0xLjI2LTEuMjVWMjJoMS4yNnY4LjEzSDI3WiIvPjxwYXRoIGlkPSJ2cGNfZ3JhZGllbnRfdG9wIiBkYXRhLW5hbWU9InZwYyBncmFkaWVudCB0b3AiIGNsYXNzPSJjbHMtMiIgZD0iTTMwLjEyLDI3aDEuMjZWMTguODhhMS4yNiwxLjI2LDAsMCwwLTEuMjYtMS4yNUgyMnYxLjI1aDguMTJaIi8+PHBhdGggaWQ9ImVuZHBvaW50cyIgY2xhc3M9ImNscy0yIiBkPSJNMjkuMTIsMjguMjVsLTIuNS0yLjVBMi4yNiwyLjI2LDAsMCwwLDI3LDI0LjUsMi41MSwyLjUxLDAsMCwwLDI0LjUsMjJhMi4xOSwyLjE5LDAsMCwwLTEuMjUuMzhsLTIuNS0yLjVWMTUuNzVoLTV2NWg0LjEzbDIuNSwyLjVBMi4yNiwyLjI2LDAsMCwwLDIyLDI0LjUsMi41MSwyLjUxLDAsMCwwLDI0LjUsMjdhMi4yNiwyLjI2LDAsMCwwLDEuMjUtLjM4bDIuNSwyLjV2NC4xM2g1di01Wk0xOS41LDE5LjVIMTdWMTdoMi41Wm01LDYuMjVhMS4yNSwxLjI1LDAsMSwxLDEuMjUtMS4yNUExLjI1LDEuMjUsMCwwLDEsMjQuNSwyNS43NVpNMzIsMzJIMjkuNVYyOS41SDMyWiIvPjxyZWN0IGNsYXNzPSJjbHMtMyIgeD0iMTQuNSIgeT0iMTQuNSIgd2lkdGg9IjIwIiBoZWlnaHQ9IjIwIi8+PC9zdmc+;fontSize=14;fontFamily=IBM Plex Sans;fontSource=fonts%2FIBMPlexSans-Regular.woff;spacingTop=-7;labelPosition=center;verticalLabelPosition=bottom;align=center;verticalAlign=top;"
	}
	return ""
}

func CreateDrawioConnectivityMapFile(network SquareTreeNodeInterface, outputFile string) {
	newLayout(network).layout()
	data := &drawioData{
		iconSize,
		fipXOffset,
		fipYOffset,
		vsiXOffset,
		vsiYOffset,
		vsiIconSize,
		hasVsiIcon(network),
		getAllNodes(network)}
	writeDrawioFile(data, outputFile)
}

func writeDrawioFile(data *drawioData, outputFile string) {
	tmpl, err := template.New("connectivityMap.drawio.tmpl").Parse(drawioTemplate)
	if err != nil {
		panic(err)
	}
	fo, err := os.Create(outputFile)
	if err != nil {
		panic(err)
	}
	// close fo on exit and check for its returned error
	defer func() {
		if err = fo.Close(); err != nil {
			panic(err)
		}
	}()
	err = tmpl.Execute(fo, data)
	if err != nil {
		panic(err)
	}
}
