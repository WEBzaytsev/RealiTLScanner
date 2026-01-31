package main

import (
	"fmt"
	"os"
	"strconv"
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
	
	// Input widgets
	sourceRadio *widget.RadioGroup
	inputEntry  *widget.Entry
	portEntry   *widget.Entry
	threadEntry *widget.Entry
	timeoutEntry *widget.Entry
	ipv6Check   *widget.Check
	verboseCheck *widget.Check
	
	// Control widgets
	startBtn    *widget.Button
	stopBtn     *widget.Button
	saveBtn     *widget.Button
	
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
	// Сначала создаем Entry (до RadioGroup)
	g.inputEntry = widget.NewEntry()
	g.inputEntry.SetPlaceHolder("Enter IP, CIDR or domain")
	
	// Source selection
	g.sourceRadio = widget.NewRadioGroup([]string{"IP/CIDR/Domain", "File", "URL"}, func(value string) {
		g.inputEntry.SetPlaceHolder(g.getPlaceholder(value))
	})
	g.sourceRadio.SetSelected("IP/CIDR/Domain")
	g.sourceRadio.Horizontal = true
	
	fileBrowseBtn := widget.NewButton("...", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err == nil && reader != nil {
				g.inputEntry.SetText(reader.URI().Path())
				reader.Close()
			}
		}, g.window)
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
	
	g.saveBtn = widget.NewButton("Save CSV", g.onSave)
	g.saveBtn.Disable()
	
	controlBox := container.NewHBox(
		g.startBtn,
		g.stopBtn,
		layout.NewSpacer(),
		g.saveBtn,
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
				// Header
				headers := []string{"IP", "Origin", "Domain", "Issuer", "Geo", "Feasible"}
				label.SetText(headers[id.Col])
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

func (g *GUI) onStart() {
	if g.isScanning {
		return
	}
	
	// Validate inputs
	if g.inputEntry.Text == "" {
		dialog.ShowError(fmt.Errorf("Please specify scan source"), g.window)
		return
	}
	
	port, err := strconv.Atoi(g.portEntry.Text)
	if err != nil || port <= 0 || port > 65535 {
		dialog.ShowError(fmt.Errorf("Invalid port"), g.window)
		return
	}
	
	threads, err := strconv.Atoi(g.threadEntry.Text)
	if err != nil || threads <= 0 {
		dialog.ShowError(fmt.Errorf("Invalid thread count"), g.window)
		return
	}
	
	timeout, err := strconv.Atoi(g.timeoutEntry.Text)
	if err != nil || timeout <= 0 {
		dialog.ShowError(fmt.Errorf("Invalid timeout"), g.window)
		return
	}
	
	// Clear previous results
	g.resultsMu.Lock()
	g.results = make([]ScanResult, 0)
	g.resultsMu.Unlock()
	g.resultsTable.Refresh()
	
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
			
			// UI обновления через fyne.Do
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
	
	// Создание Scanner в фоне чтобы не блокировать UI при загрузке GeoIP
	g.statusText.Set("Initializing...")
	g.startBtn.Disable()
	go func() {
		g.scanner = NewScanner(config, callbacks)
		
		// После инициализации начать сканирование
		// Update UI state
		fyne.Do(func() {
			g.isScanning = true
			g.stopBtn.Enable()
			g.saveBtn.Disable()
			g.statusText.Set("Scanning started...")
		})
		
		// Start scanning in background
		go g.runScan()
	}()
}

func (g *GUI) runScan() {
	defer func() {
		g.resultsMu.Lock()
		count := len(g.results)
		g.resultsMu.Unlock()
		
		fyne.Do(func() {
			g.isScanning = false
			g.startBtn.Enable()
			g.stopBtn.Disable()
			g.saveBtn.Enable()
			g.statusText.Set(fmt.Sprintf("Scanning completed. Found: %d", count))
		})
	}()
	
	var hostChan <-chan Host
	source := g.sourceRadio.Selected
	input := g.inputEntry.Text
	
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

func (g *GUI) onSave() {
	dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
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
		for _, result := range g.results {
			if result.Feasible {
				line := fmt.Sprintf("%s,%s,%s,\"%s\",%s\n",
					result.IP, result.Origin, result.Domain, result.Issuer, result.GeoCode)
				_, _ = writer.Write([]byte(line))
			}
		}
		
		dialog.ShowInformation("Saved",
			fmt.Sprintf("Saved %d results", len(g.results)), g.window)
		
	}, g.window)
	
	// Set default filename
	dialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {}, g.window)
	dialog.SetFileName("scan_results.csv")
	dialog.SetFilter(storage.NewExtensionFileFilter([]string{".csv"}))
}
