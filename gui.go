package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
	"github.com/xuri/excelize/v2"
)

type GUI struct {
	app        fyne.App
	window     fyne.Window
	scanner    *Scanner
	results    []ScanResult
	resultsMu  sync.Mutex
	isScanning bool
	statusText binding.String
	logText    binding.String
	
	// Sorting state
	sortColumn    int
	sortAscending bool
	
	// Double-click detection
	lastClickCell widget.TableCellID
	lastClickTime time.Time
	
	// Input widgets
	sourceRadio *widget.RadioGroup
	inputEntry  *widget.Entry
	portEntry   *widget.Entry
	threadEntry *widget.Entry
	timeoutEntry *widget.Entry
	ipv6Check   *widget.Check
	verboseCheck *widget.Check
	
	// Control widgets
	startBtn     *widget.Button
	stopBtn      *widget.Button
	saveCSVBtn   *widget.Button
	saveExcelBtn *widget.Button
	
	// Results table
	resultsTable *widget.Table
	
	// Log area
	logScroll *container.Scroll
}

func runGUI() {
	myApp := app.New()
	myWindow := myApp.NewWindow("RealiTLScanner")
	myWindow.Resize(fyne.NewSize(1000, 700))
	
	gui := &GUI{
		app:      myApp,
		window:   myWindow,
		results:  make([]ScanResult, 0),
	}
	
	gui.statusText = binding.NewString()
	gui.statusText.Set("Ready to scan")
	
	gui.logText = binding.NewString()
	gui.logText.Set("")
	
	content := gui.buildUI()
	myWindow.SetContent(content)
	myWindow.ShowAndRun()
}

func (g *GUI) buildUI() fyne.CanvasObject {
	// Create Entry first (before RadioGroup)
	g.inputEntry = widget.NewEntry()
	g.inputEntry.SetPlaceHolder("Enter IP, CIDR or domain")
	
	// Source selection
	g.sourceRadio = widget.NewRadioGroup([]string{"IP/CIDR/Domain", "File", "URL"}, func(value string) {
		g.inputEntry.SetPlaceHolder(g.getPlaceholder(value))
	})
	g.sourceRadio.SetSelected("IP/CIDR/Domain")
	g.sourceRadio.Horizontal = true
	
	fileBrowseBtn := widget.NewButton("...", func() {
		fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err == nil && reader != nil {
				g.inputEntry.SetText(reader.URI().Path())
				reader.Close()
			}
		}, g.window)
		
		// Set filter for text files
		fileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".txt"}))
		fileDialog.Show()
	})
	
	inputContainer := container.NewBorder(nil, nil, nil, fileBrowseBtn, g.inputEntry)
	
	sourceBox := container.NewVBox(
		widget.NewLabel("Source:"),
		g.sourceRadio,
		inputContainer,
	)
	
	// Settings
	g.portEntry = widget.NewEntry()
	g.portEntry.SetText("443")
	g.portEntry.SetPlaceHolder("443")
	
	g.threadEntry = widget.NewEntry()
	g.threadEntry.SetText("2")
	g.threadEntry.SetPlaceHolder("2")
	
	g.timeoutEntry = widget.NewEntry()
	g.timeoutEntry.SetText("10")
	g.timeoutEntry.SetPlaceHolder("10")
	
	g.ipv6Check = widget.NewCheck("IPv6", nil)
	g.verboseCheck = widget.NewCheck("Verbose", nil)
	
	settingsGrid := container.New(layout.NewGridLayout(6),
		widget.NewLabel("Port:"), g.portEntry,
		widget.NewLabel("Threads:"), g.threadEntry,
		widget.NewLabel("Timeout:"), g.timeoutEntry,
	)
	
	checksBox := container.NewHBox(g.ipv6Check, g.verboseCheck)
	
	settingsBox := container.NewVBox(settingsGrid, checksBox)
	
	// Control buttons
	g.startBtn = widget.NewButton("Start", g.onStart)
	g.startBtn.Importance = widget.HighImportance
	
	g.stopBtn = widget.NewButton("Stop", g.onStop)
	g.stopBtn.Disable()
	
	g.saveCSVBtn = widget.NewButton("Save CSV", g.onSaveCSV)
	g.saveCSVBtn.Disable()
	
	g.saveExcelBtn = widget.NewButton("Save Excel", g.onSaveExcel)
	g.saveExcelBtn.Disable()
	
	controlBox := container.NewHBox(
		g.startBtn,
		g.stopBtn,
		layout.NewSpacer(),
		g.saveCSVBtn,
		g.saveExcelBtn,
	)
	
	// Results table
	g.resultsTable = widget.NewTable(
		func() (int, int) {
			g.resultsMu.Lock()
			defer g.resultsMu.Unlock()
			return len(g.results) + 1, 6
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("Cell")
		},
		func(id widget.TableCellID, cell fyne.CanvasObject) {
			label := cell.(*widget.Label)
			g.resultsMu.Lock()
			defer g.resultsMu.Unlock()
			
			if id.Row == 0 {
				// Header with sort indicator
				headers := []string{"IP", "Origin", "Domain", "Issuer", "Geo", "Feasible"}
				headerText := headers[id.Col]
				if g.sortColumn == id.Col {
					if g.sortAscending {
						headerText += " ▲"
					} else {
						headerText += " ▼"
					}
				}
				label.SetText(headerText)
				label.TextStyle = fyne.TextStyle{Bold: true}
			} else {
				// Data
				if id.Row-1 < len(g.results) {
					result := g.results[id.Row-1]
					var text string
					switch id.Col {
					case 0:
						text = result.IP
					case 1:
						text = result.Origin
					case 2:
						text = result.Domain
					case 3:
						text = result.Issuer
					case 4:
						text = result.GeoCode
					case 5:
						if result.Feasible {
							text = "✓"
						} else {
							text = "✗"
						}
					}
					label.SetText(text)
					label.TextStyle = fyne.TextStyle{}
				}
			}
		},
	)
	
	// Add click handler for sorting and double-click copying
	g.resultsTable.OnSelected = func(id widget.TableCellID) {
		now := time.Now()
		
		if id.Row == 0 {
			// Clicked on header - sort by this column
			g.sortByColumn(id.Col)
		} else {
			// Clicked on data cell - check for double-click
			isDoubleClick := id.Row == g.lastClickCell.Row && 
							 id.Col == g.lastClickCell.Col && 
							 now.Sub(g.lastClickTime) < 500*time.Millisecond
			
			if isDoubleClick {
				// Double-click detected - copy to clipboard
				g.resultsMu.Lock()
				if id.Row-1 < len(g.results) {
					result := g.results[id.Row-1]
					var text string
					switch id.Col {
					case 0:
						text = result.IP
					case 1:
						text = result.Origin
					case 2:
						text = result.Domain
					case 3:
						text = result.Issuer
					case 4:
						text = result.GeoCode
					case 5:
						if result.Feasible {
							text = "true"
						} else {
							text = "false"
						}
					}
					g.resultsMu.Unlock()
					
					if text != "" {
						g.window.Clipboard().SetContent(text)
						// Show brief notification
						fyne.Do(func() {
							oldStatus, _ := g.statusText.Get()
							g.statusText.Set(fmt.Sprintf("Copied: %s", text))
							time.AfterFunc(2*time.Second, func() {
								fyne.Do(func() {
									currentStatus, _ := g.statusText.Get()
									if strings.HasPrefix(currentStatus, "Copied:") {
										g.statusText.Set(oldStatus)
									}
								})
							})
						})
					}
					
					// Reset click tracking
					g.lastClickCell = widget.TableCellID{}
					g.lastClickTime = time.Time{}
				} else {
					g.resultsMu.Unlock()
				}
			} else {
				// First click - remember for double-click detection
				g.lastClickCell = id
				g.lastClickTime = now
			}
		}
		// Deselect after processing
		g.resultsTable.UnselectAll()
	}
	
	g.resultsTable.SetColumnWidth(0, 120)
	g.resultsTable.SetColumnWidth(1, 150)
	g.resultsTable.SetColumnWidth(2, 200)
	g.resultsTable.SetColumnWidth(3, 200)
	g.resultsTable.SetColumnWidth(4, 50)
	g.resultsTable.SetColumnWidth(5, 80)
	
	resultsContainer := container.NewBorder(
		widget.NewLabel("Results:"),
		nil, nil, nil,
		g.resultsTable,
	)
	
	// Status and log
	statusLabel := widget.NewLabelWithData(g.statusText)
	
	logLabel := widget.NewLabelWithData(g.logText)
	logLabel.Wrapping = fyne.TextWrapWord
	g.logScroll = container.NewVScroll(logLabel)
	g.logScroll.SetMinSize(fyne.NewSize(0, 100))
	
	logContainer := container.NewBorder(
		widget.NewLabel("Log:"),
		nil, nil, nil,
		g.logScroll,
	)
	
	// Main layout
	topSection := container.NewVBox(
		sourceBox,
		widget.NewSeparator(),
		settingsBox,
		widget.NewSeparator(),
		controlBox,
		widget.NewSeparator(),
	)
	
	splitContainer := container.NewVSplit(
		resultsContainer,
		logContainer,
	)
	splitContainer.SetOffset(0.7)
	
	mainContainer := container.NewBorder(
		topSection,
		container.NewVBox(widget.NewSeparator(), statusLabel),
		nil, nil,
		splitContainer,
	)
	
	return mainContainer
}

func (g *GUI) getPlaceholder(source string) string {
	switch source {
	case "IP/CIDR/Domain":
		return "Enter IP, CIDR or domain"
	case "File":
		return "Select file with address list"
	case "URL":
		return "Enter URL to parse domains from"
	default:
		return ""
	}
}

func sanitizeInput(input string) string {
	// Remove leading/trailing whitespace
	input = strings.TrimSpace(input)
	
	// Remove all whitespace characters (spaces, tabs, newlines)
	input = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, input)
	
	return input
}

func sanitizeNumericInput(input string) string {
	// Remove all non-digit characters
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, strings.TrimSpace(input))
}

func (g *GUI) onStart() {
	if g.isScanning {
		return
	}
	
	// Sanitize and validate inputs
	sanitizedInput := sanitizeInput(g.inputEntry.Text)
	if sanitizedInput == "" {
		dialog.ShowError(fmt.Errorf("Please specify scan source"), g.window)
		return
	}
	
	// Update input field with sanitized value
	if sanitizedInput != g.inputEntry.Text {
		g.inputEntry.SetText(sanitizedInput)
	}
	
	// Sanitize numeric inputs
	portStr := sanitizeNumericInput(g.portEntry.Text)
	if portStr == "" {
		portStr = "443"
		g.portEntry.SetText(portStr)
	}
	
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		dialog.ShowError(fmt.Errorf("Invalid port"), g.window)
		return
	}
	
	threadStr := sanitizeNumericInput(g.threadEntry.Text)
	if threadStr == "" {
		threadStr = "2"
		g.threadEntry.SetText(threadStr)
	}
	
	threads, err := strconv.Atoi(threadStr)
	if err != nil || threads <= 0 {
		dialog.ShowError(fmt.Errorf("Invalid thread count"), g.window)
		return
	}
	
	timeoutStr := sanitizeNumericInput(g.timeoutEntry.Text)
	if timeoutStr == "" {
		timeoutStr = "10"
		g.timeoutEntry.SetText(timeoutStr)
	}
	
	timeout, err := strconv.Atoi(timeoutStr)
	if err != nil || timeout <= 0 {
		dialog.ShowError(fmt.Errorf("Invalid timeout"), g.window)
		return
	}
	
	// Clear previous results and log
	g.resultsMu.Lock()
	g.results = make([]ScanResult, 0)
	g.resultsMu.Unlock()
	g.resultsTable.Refresh()
	g.logText.Set("") // Clear log
	
	// Setup config
	config := &ScanConfig{
		Port:       port,
		Thread:     threads,
		Timeout:    timeout,
		EnableIPv6: g.ipv6Check.Checked,
		Verbose:    g.verboseCheck.Checked,
	}
	
	callbacks := &ScanCallbacks{
		OnResult: func(result ScanResult) {
			g.resultsMu.Lock()
			g.results = append(g.results, result)
			count := len(g.results)
			g.resultsMu.Unlock()
			
			// Update UI through fyne.Do
			fyne.Do(func() {
				g.resultsTable.Refresh()
				g.statusText.Set(fmt.Sprintf("Scanning... Found: %d", count))
			})
		},
		OnLog: func(level, message string) {
			currentLog, _ := g.logText.Get()
			timestamp := time.Now().Format("15:04:05")
			newLog := fmt.Sprintf("[%s] %s: %s\n%s", timestamp, level, message, currentLog)
			if len(newLog) > 10000 {
				newLog = newLog[:10000]
			}
			fyne.Do(func() {
				g.logText.Set(newLog)
			})
		},
		OnGeoStatus: func(status string) {
			fyne.Do(func() {
				g.statusText.Set(status)
			})
		},
	}
	
	// Create Scanner in background to avoid blocking UI during GeoIP loading
	g.statusText.Set("Initializing...")
	g.startBtn.Disable()
	go func() {
		g.scanner = NewScanner(config, callbacks)
		
		// After initialization start scanning
		// Update UI state
		fyne.Do(func() {
			g.isScanning = true
			g.stopBtn.Enable()
			g.saveCSVBtn.Disable()
			g.saveExcelBtn.Disable()
			g.statusText.Set("Scanning started...")
		})
		
		// Start scanning in background
		go g.runScan()
	}()
}

func (g *GUI) runScan() {
	// Check that scanner is initialized
	if g.scanner == nil {
		fyne.Do(func() {
			g.statusText.Set("Error: Scanner not initialized")
			g.isScanning = false
			g.startBtn.Enable()
			g.stopBtn.Disable()
		})
		return
	}
	
	// Log scan start
	if g.scanner.Callbacks != nil && g.scanner.Callbacks.OnLog != nil {
		source := g.sourceRadio.Selected
		input := sanitizeInput(g.inputEntry.Text)
		g.scanner.Callbacks.OnLog("info", fmt.Sprintf("Starting scan: %s - %s", source, input))
	}
	
	defer func() {
		g.resultsMu.Lock()
		count := len(g.results)
		g.resultsMu.Unlock()
		
		// Log scan completion
		if g.scanner != nil && g.scanner.Callbacks != nil && g.scanner.Callbacks.OnLog != nil {
			g.scanner.Callbacks.OnLog("info", fmt.Sprintf("Scan completed. Found: %d results", count))
		}
		
		fyne.Do(func() {
			g.isScanning = false
			g.startBtn.Enable()
			g.stopBtn.Disable()
			if count > 0 {
				g.saveCSVBtn.Enable()
				g.saveExcelBtn.Enable()
			}
			g.statusText.Set(fmt.Sprintf("Scanning completed. Found: %d", count))
		})
	}()
	
	var hostChan <-chan Host
	source := g.sourceRadio.Selected
	input := sanitizeInput(g.inputEntry.Text)
	
	switch source {
	case "IP/CIDR/Domain":
		hostChan = IterateAddr(input, g.scanner.Config.EnableIPv6)
	case "File":
		f, err := os.Open(input)
		if err != nil {
			if g.scanner.Callbacks != nil && g.scanner.Callbacks.OnLog != nil {
				g.scanner.Callbacks.OnLog("error", fmt.Sprintf("Failed to open file: %v", err))
			}
			return
		}
		defer f.Close()
		hostChan = Iterate(f, g.scanner.Config.EnableIPv6)
	case "URL":
		// TODO: implement URL parsing
		if g.scanner.Callbacks != nil && g.scanner.Callbacks.OnLog != nil {
			g.scanner.Callbacks.OnLog("info", "URL parsing not yet implemented in GUI")
		}
		return
	}
	
	var wg sync.WaitGroup
	wg.Add(g.scanner.Config.Thread)
	
	for i := 0; i < g.scanner.Config.Thread; i++ {
		go func() {
			defer wg.Done()
			for host := range hostChan {
				select {
				case <-g.scanner.Context().Done():
					return
				default:
					ScanTLSWithCallbacks(host, g.scanner)
				}
			}
		}()
	}
	
	wg.Wait()
}

func (g *GUI) onStop() {
	if g.scanner != nil {
		g.scanner.Stop()
		g.statusText.Set("Stopping scan...")
	}
}

func (g *GUI) onSaveCSV() {
	g.resultsMu.Lock()
	resultsCount := len(g.results)
	g.resultsMu.Unlock()
	
	if resultsCount == 0 {
		dialog.ShowInformation("No Results", "No results to save", g.window)
		return
	}
	
	// Generate default filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	defaultFilename := fmt.Sprintf("scan_results_%s.csv", timestamp)
	
	// Create file save dialog
	fileDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil {
			dialog.ShowError(err, g.window)
			return
		}
		if writer == nil {
			return
		}
		defer writer.Close()
		
		g.resultsMu.Lock()
		defer g.resultsMu.Unlock()
		
		// Write CSV header
		_, _ = writer.Write([]byte("IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE\n"))
		
		// Write results
		savedCount := 0
		for _, result := range g.results {
			if result.Feasible {
				line := fmt.Sprintf("%s,%s,%s,\"%s\",%s\n",
					result.IP, result.Origin, result.Domain, result.Issuer, result.GeoCode)
				_, _ = writer.Write([]byte(line))
				savedCount++
			}
		}
		
		dialog.ShowInformation("Saved",
			fmt.Sprintf("Saved %d feasible results", savedCount), g.window)
		
	}, g.window)
	
	// Set default filename and filter
	fileDialog.SetFileName(defaultFilename)
	fileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".csv"}))
	fileDialog.Show()
}

func (g *GUI) onSaveExcel() {
	g.resultsMu.Lock()
	resultsCount := len(g.results)
	g.resultsMu.Unlock()
	
	if resultsCount == 0 {
		dialog.ShowInformation("No Results", "No results to save", g.window)
		return
	}
	
	// Generate default filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	defaultFilename := fmt.Sprintf("scan_results_%s.xlsx", timestamp)
	
	// Create file save dialog
	fileDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil {
			dialog.ShowError(err, g.window)
			return
		}
		if writer == nil {
			return
		}
		defer writer.Close()
		
		if err := g.saveToExcel(writer); err != nil {
			dialog.ShowError(fmt.Errorf("Failed to save Excel: %v", err), g.window)
		} else {
			g.resultsMu.Lock()
			savedCount := 0
			for _, result := range g.results {
				if result.Feasible {
					savedCount++
				}
			}
			g.resultsMu.Unlock()
			
			dialog.ShowInformation("Saved",
				fmt.Sprintf("Saved %d feasible results", savedCount), g.window)
		}
		
	}, g.window)
	
	// Set default filename and filter
	fileDialog.SetFileName(defaultFilename)
	fileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".xlsx"}))
	fileDialog.Show()
}

func (g *GUI) sortByColumn(col int) {
	g.resultsMu.Lock()
	defer g.resultsMu.Unlock()
	
	// Toggle sort direction if same column, otherwise ascending
	if g.sortColumn == col {
		g.sortAscending = !g.sortAscending
	} else {
		g.sortColumn = col
		g.sortAscending = true
	}
	
	// Sort results based on column
	sort.Slice(g.results, func(i, j int) bool {
		var less bool
		switch col {
		case 0: // IP
			less = g.results[i].IP < g.results[j].IP
		case 1: // Origin
			less = g.results[i].Origin < g.results[j].Origin
		case 2: // Domain
			less = g.results[i].Domain < g.results[j].Domain
		case 3: // Issuer
			less = g.results[i].Issuer < g.results[j].Issuer
		case 4: // Geo
			less = g.results[i].GeoCode < g.results[j].GeoCode
		case 5: // Feasible
			less = !g.results[i].Feasible && g.results[j].Feasible
		default:
			less = false
		}
		
		if !g.sortAscending {
			less = !less
		}
		return less
	})
	
	// Refresh table
	fyne.Do(func() {
		g.resultsTable.Refresh()
	})
}

func (g *GUI) saveToExcel(writer fyne.URIWriteCloser) error {
	g.resultsMu.Lock()
	defer g.resultsMu.Unlock()
	
	// Create new Excel file
	f := excelize.NewFile()
	defer f.Close()
	
	sheetName := "Scan Results"
	index, err := f.NewSheet(sheetName)
	if err != nil {
		return err
	}
	f.SetActiveSheet(index)
	
	// Create header style
	headerStyle, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Bold: true,
			Size: 12,
		},
		Fill: excelize.Fill{
			Type:    "pattern",
			Pattern: 1,
			Color:   []string{"#E0E0E0"},
		},
		Alignment: &excelize.Alignment{
			Horizontal: "center",
			Vertical:   "center",
		},
	})
	if err != nil {
		return err
	}
	
	// Write headers
	headers := []string{"IP", "Origin", "Domain", "Issuer", "Geo", "TLS Version", "ALPN", "Feasible"}
	for col, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, 1)
		f.SetCellValue(sheetName, cell, header)
		f.SetCellStyle(sheetName, cell, cell, headerStyle)
	}
	
	// Set column widths
	f.SetColWidth(sheetName, "A", "A", 15) // IP
	f.SetColWidth(sheetName, "B", "B", 20) // Origin
	f.SetColWidth(sheetName, "C", "C", 30) // Domain
	f.SetColWidth(sheetName, "D", "D", 40) // Issuer
	f.SetColWidth(sheetName, "E", "E", 8)  // Geo
	f.SetColWidth(sheetName, "F", "F", 12) // TLS Version
	f.SetColWidth(sheetName, "G", "G", 10) // ALPN
	f.SetColWidth(sheetName, "H", "H", 10) // Feasible
	
	// Write data (only feasible results)
	row := 2
	for _, result := range g.results {
		if result.Feasible {
			f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), result.IP)
			f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), result.Origin)
			f.SetCellValue(sheetName, fmt.Sprintf("C%d", row), result.Domain)
			f.SetCellValue(sheetName, fmt.Sprintf("D%d", row), result.Issuer)
			f.SetCellValue(sheetName, fmt.Sprintf("E%d", row), result.GeoCode)
			f.SetCellValue(sheetName, fmt.Sprintf("F%d", row), result.TLSVersion)
			f.SetCellValue(sheetName, fmt.Sprintf("G%d", row), result.ALPN)
			f.SetCellValue(sheetName, fmt.Sprintf("H%d", row), "Yes")
			row++
		}
	}
	
	// Enable auto-filter
	if row > 2 {
		lastCell, _ := excelize.CoordinatesToCellName(len(headers), row-1)
		f.AutoFilter(sheetName, fmt.Sprintf("A1:%s", lastCell), []excelize.AutoFilterOptions{})
	}
	
	// Write to the provided writer
	buf, err := f.WriteToBuffer()
	if err != nil {
		return err
	}
	
	_, err = writer.Write(buf.Bytes())
	return err
}

