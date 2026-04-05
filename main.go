package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/SharokhAtaie/extractify/scanner"
	"github.com/briandowns/spinner"
	"github.com/logrusorgru/aurora/v4"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	urlutil "github.com/projectdiscovery/utils/url"
)

type options struct {
	file           string
	url            string
	list           string
	output         string
	json           bool
	endpoint       bool
	secret         bool
	all            bool
	urls           bool
	header         string
	concurrent     int
	timeout        int
	customPatterns string
	filterExt      goflags.StringSlice
	version        bool
	noColor        bool
	// extract* are resolved after parsing: which flows to run (see resolveExtractModes). Combinations allowed.
	extractEndpoints bool
	extractURLs      bool
	extractSecrets   bool
	dedup            bool
}

// Version of the current build
const VERSION = "1.5.0"

func main() {
	opt := &options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("A tool for extracting Endpoints, URLs and Secrets from various sources")

	flagSet.CreateGroup("Inputs", "Inputs",
		flagSet.StringVarP(&opt.url, "url", "u", "", "URL for scanning"),
		flagSet.StringVarP(&opt.list, "list", "l", "", "List of URLs for scanning"),
		flagSet.StringVarP(&opt.file, "file", "f", "", "Local file or directory for scanning"),
	)

	flagSet.CreateGroup("Extract", "Extracts",
		flagSet.BoolVarP(&opt.endpoint, "endpoints", "ee", false, "Extract endpoints"),
		flagSet.BoolVarP(&opt.urls, "urls", "eu", false, "Extract urls"),
		flagSet.BoolVarP(&opt.secret, "secrets", "es", false, "Extract secrets"),
		flagSet.BoolVarP(&opt.all, "all", "ea", false, "Extract all"),
	)

	flagSet.CreateGroup("Others", "Others",
		flagSet.StringVarP(&opt.header, "header", "H", "", "Set custom header"),
		flagSet.IntVarP(&opt.concurrent, "concurrent", "c", 10, "Number of concurrent workers"),
		flagSet.IntVarP(&opt.timeout, "timeout", "t", 20, "Timeout in seconds for HTTP requests"),
		flagSet.StringVarP(&opt.output, "output", "o", "", "Output file to write results"),
		flagSet.BoolVarP(&opt.json, "json", "j", false, "Print JSON to stdout when -o is omitted; with -o, write JSON only (no human-readable console output)"),
		flagSet.StringVarP(&opt.customPatterns, "patterns", "p", "", "Custom regex patterns file"),
		flagSet.BoolVarP(&opt.version, "version", "V", false, "Show version information"),
		flagSet.BoolVarP(&opt.noColor, "no-color", "nc", false, "Disable colorized output"),
		flagSet.BoolVar(&opt.dedup, "dedup", false, "Drop duplicate URLs, endpoints, and secret matches across all sources (first occurrence wins)"),
		flagSet.StringSliceVarP(&opt.filterExt, "filter-extension", "fe", []string{"woff2"}, "List of extensions svg,png (comma-separated)", goflags.FileCommaSeparatedStringSliceOptions),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Could not parse flags: %s\n", err)
	}

	resolveExtractModes(opt)

	// Show version and exit if -V is used
	if opt.version {
		fmt.Printf("Extractify version %s\n", VERSION)
		return
	}

	if opt.url == "" && opt.list == "" && opt.file == "" && !fileutil.HasStdin() {
		printUsage()
		return
	}

	// Create results channel with sufficient buffer
	resultsChan := make(chan ScanResult, 100)

	// Create wait group for workers
	var wg sync.WaitGroup

	// Start the results collector
	var outputFile *os.File
	var err error
	if opt.output != "" {
		outputFile, err = os.Create(opt.output)
		if err != nil {
			gologger.Fatal().Msgf("Failed to create output file: %v", err)
		}
		defer outputFile.Close()
	}

	humanConsole := opt.output == "" && !opt.json
	writeJSON := opt.output != "" || opt.json

	collectorDone := make(chan bool)
	go func() {
		collectResults(resultsChan, outputFile, opt, humanConsole, writeJSON)
		collectorDone <- true
	}()

	if opt.file != "" {
		// Process local file
		processSingleFile(opt.file, opt, resultsChan)
		close(resultsChan)
		<-collectorDone // Wait for collector to finish
		return
	}

	var URLs []string

	// Add single URL if provided
	if opt.url != "" {
		URLs = append(URLs, opt.url)
	}

	// Add URLs from file if provided
	if opt.list != "" {
		if fileutil.FileExists(opt.list) {
			bin, err := os.ReadFile(opt.list)
			if err != nil {
				gologger.Error().Msgf("Failed to read file %v: %v", opt.list, err)
			} else {
				for _, url := range strings.Fields(string(bin)) {
					if url != "" {
						URLs = append(URLs, url)
					}
				}
			}
		} else {
			gologger.Fatal().Msgf("File %s does not exist", opt.list)
		}
	}

	// Add URLs from stdin if provided
	if fileutil.HasStdin() {
		bin, err := io.ReadAll(os.Stdin)
		if err != nil {
			gologger.Error().Msgf("Failed to read from stdin: %v", err)
		} else {
			for _, url := range strings.Fields(string(bin)) {
				if url != "" {
					URLs = append(URLs, url)
				}
			}
		}
	}

	// Create a job queue
	jobChan := make(chan string, opt.concurrent)

	// Start workers
	for i := 0; i < opt.concurrent; i++ {
		wg.Add(1)
		go worker(jobChan, resultsChan, &wg, opt)
	}

	// Send jobs to workers
	for _, url := range URLs {
		jobChan <- url
	}

	// Close the job channel to signal workers to exit
	close(jobChan)

	// Wait for all workers to finish
	wg.Wait()

	// Close the results channel to signal the collector to exit
	close(resultsChan)

	// Wait for collector to finish
	<-collectorDone

	// Print completion message
	if opt.output != "" {
		if !opt.noColor {
			gologger.Info().Msgf("Results saved to %s", opt.output)
		} else {
			fmt.Printf("[INF] Results saved to %s\n", opt.output)
		}
	}
}

// resolveExtractModes sets opt.extract* from flags: -ea runs all; with no -ee/-eu/-es runs all;
// any combination of -ee/-eu/-es enables those flows together (e.g. -ee -es → endpoints + secrets).
func resolveExtractModes(opt *options) {
	if opt.all {
		opt.extractEndpoints = true
		opt.extractURLs = true
		opt.extractSecrets = true
		return
	}
	if !opt.endpoint && !opt.urls && !opt.secret {
		opt.extractEndpoints = true
		opt.extractURLs = true
		opt.extractSecrets = true
		return
	}
	opt.extractEndpoints = opt.endpoint
	opt.extractURLs = opt.urls
	opt.extractSecrets = opt.secret
}

// ScanResult represents a result from scanning
type ScanResult struct {
	Source    string
	Secrets   []scanner.SecretMatched
	URLs      []string
	Endpoints []string
	Error     error
}

// Worker function to process URLs concurrently
func worker(jobs <-chan string, results chan<- ScanResult, wg *sync.WaitGroup, opt *options) {
	defer wg.Done()

	for url := range jobs {
		result := ScanResult{Source: url}

		data, err := request(url, opt.header, opt.timeout)
		if err != nil {
			result.Error = err
			results <- result
			continue
		}

		secrets, urls, endpoints := run(data, url, opt.filterExt, opt.customPatterns, opt.extractSecrets, opt.extractURLs, opt.extractEndpoints)
		result.Secrets = secrets
		result.URLs = urls
		result.Endpoints = endpoints

		results <- result
	}
}

// Process a single file
func processSingleFile(filePath string, opt *options, results chan<- ScanResult) {
	// Check if the path is a directory
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if !opt.noColor {
			gologger.Error().Msgf("Failed to read file %v: %v", filePath, err)
		} else {
			fmt.Printf("[ERR] Failed to read file %v: %v\n", filePath, err)
		}
		return
	}

	if fileInfo.IsDir() {
		// Process directory recursively
		processDirectory(filePath, opt, results)
		return
	}

	// Process single file
	if !opt.noColor {
		gologger.Info().Msgf("Processing file: %s", filePath)
	} else {
		fmt.Printf("[INF] Processing file: %s\n", filePath)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if !opt.noColor {
			gologger.Error().Msgf("Failed to read file %v: %v", filePath, err)
		} else {
			fmt.Printf("[ERR] Failed to read file %v: %v\n", filePath, err)
		}
		return
	}

	secrets, urls, endpoints := run(data, filePath, opt.filterExt, opt.customPatterns, opt.extractSecrets, opt.extractURLs, opt.extractEndpoints)

	results <- ScanResult{
		Source:    filePath,
		Secrets:   secrets,
		URLs:      urls,
		Endpoints: endpoints,
	}

	// Wait a moment to ensure all results are processed
	time.Sleep(100 * time.Millisecond)
}

// Process a directory recursively
func processDirectory(dirPath string, opt *options, results chan<- ScanResult) {

	spin := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	spinnerSuffix := " Processing directory: " + dirPath + "\n\n"
	spin.Suffix = spinnerSuffix

	// Disable spinner colors when no-color is set
	if opt.noColor {
		spin.Color("reset") // Use default terminal color
	}

	spin.Start()

	err := filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				if !opt.noColor {
					gologger.Error().Msgf("Failed to read file %v: %v", path, err)
				} else {
					fmt.Printf("[ERR] Failed to read file %v: %v\n", path, err)
				}
				return nil
			}

			secrets, urls, endpoints := run(data, path, opt.filterExt, opt.customPatterns, opt.extractSecrets, opt.extractURLs, opt.extractEndpoints)

			results <- ScanResult{
				Source:    path,
				Secrets:   secrets,
				URLs:      urls,
				Endpoints: endpoints,
			}
		}
		return nil
	})

	// Always stop the spinner
	spin.Stop()

	if err != nil {
		if !opt.noColor {
			gologger.Error().Msgf("Error walking directory %v: %v", dirPath, err)
		} else {
			fmt.Printf("[ERR] Error walking directory %v: %v\n", dirPath, err)
		}
	}
}

// Collect and process results
func collectResults(results <-chan ScanResult, outputFile *os.File, opt *options, humanConsole, writeJSON bool) {
	var aggregated []ScanResult
	needAgg := writeJSON || (humanConsole && opt.dedup)

	for result := range results {
		if result.Error != nil {
			if !opt.noColor {
				gologger.Error().Msgf("Error processing %s: %v", result.Source, result.Error)
			} else {
				fmt.Printf("[ERR] Error processing %s: %v\n", result.Source, result.Error)
			}
			continue
		}

		if humanConsole && !opt.dedup {
			handleResults(opt.extractEndpoints, opt.extractURLs, opt.extractSecrets,
				result.Secrets, result.URLs, result.Endpoints, result.Source, nil, !opt.noColor)
		}

		if needAgg {
			aggregated = append(aggregated, result)
		}
	}

	outData := aggregated
	if opt.dedup && len(aggregated) > 0 {
		outData = dedupScanResults(aggregated, opt)
	}

	if humanConsole && opt.dedup {
		for _, r := range outData {
			handleResults(opt.extractEndpoints, opt.extractURLs, opt.extractSecrets,
				r.Secrets, r.URLs, r.Endpoints, r.Source, nil, !opt.noColor)
		}
	}

	if !writeJSON {
		return
	}

	var out io.Writer
	switch {
	case opt.output != "":
		out = outputFile
	default:
		out = os.Stdout
	}

	if err := encodeJSONResults(out, outData, opt); err != nil {
		if !opt.noColor {
			gologger.Error().Msgf("failed to write json results: %v", err)
		} else {
			fmt.Printf("[ERR] failed to write json results: %v\n", err)
		}
	}
}

// dedupScanResults keeps first-seen order across sources: URLs, endpoints, and secret Match strings are unique globally.
// Rows with no remaining hits for enabled extract types are dropped.
func dedupScanResults(in []ScanResult, opt *options) []ScanResult {
	seenURL := make(map[string]struct{})
	seenEP := make(map[string]struct{})
	seenSecret := make(map[string]struct{})
	out := make([]ScanResult, 0, len(in))

	for _, r := range in {
		nr := ScanResult{Source: r.Source}
		if opt.extractURLs {
			for _, u := range r.URLs {
				if _, ok := seenURL[u]; ok {
					continue
				}
				seenURL[u] = struct{}{}
				nr.URLs = append(nr.URLs, u)
			}
		}
		if opt.extractEndpoints {
			for _, e := range r.Endpoints {
				if _, ok := seenEP[e]; ok {
					continue
				}
				seenEP[e] = struct{}{}
				nr.Endpoints = append(nr.Endpoints, e)
			}
		}
		if opt.extractSecrets {
			for _, s := range r.Secrets {
				if _, ok := seenSecret[s.Match]; ok {
					continue
				}
				seenSecret[s.Match] = struct{}{}
				nr.Secrets = append(nr.Secrets, s)
			}
		}
		if !scanResultHasAnyFinding(nr, opt) {
			continue
		}
		out = append(out, nr)
	}
	return out
}

func scanResultHasAnyFinding(r ScanResult, opt *options) bool {
	if opt.extractURLs && len(r.URLs) > 0 {
		return true
	}
	if opt.extractEndpoints && len(r.Endpoints) > 0 {
		return true
	}
	if opt.extractSecrets && len(r.Secrets) > 0 {
		return true
	}
	return false
}

func encodeJSONResults(w io.Writer, aggregated []ScanResult, opt *options) error {
	type jsonRow struct {
		Source    string   `json:"source"`
		URLs      []string `json:"urls,omitempty"`
		Endpoints []string `json:"endpoints,omitempty"`
		Secrets   []string `json:"secrets,omitempty"`
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	rows := make([]jsonRow, 0, len(aggregated))
	for _, r := range aggregated {
		var secretMatches []string
		for _, s := range r.Secrets {
			secretMatches = append(secretMatches, s.Match)
		}

		if !scanResultHasAnyFinding(r, opt) {
			continue
		}

		jr := jsonRow{Source: r.Source}
		if opt.extractURLs && len(r.URLs) > 0 {
			jr.URLs = r.URLs
		}
		if opt.extractEndpoints && len(r.Endpoints) > 0 {
			jr.Endpoints = r.Endpoints
		}
		if opt.extractSecrets && len(secretMatches) > 0 {
			jr.Secrets = secretMatches
		}
		rows = append(rows, jr)
	}

	return enc.Encode(rows)
}

func run(Data []byte, Source string, FilterExtension []string, customPatternsFile string, wantSecrets, wantURLs, wantEndpoints bool) ([]scanner.SecretMatched, []string, []string) {
	var sortedUrls []string
	var sortedEndpoints []string

	var secretMatchResult []scanner.SecretMatched
	if wantSecrets {
		if customPatternsFile != "" {
			customSecrets, err := scanner.LoadCustomSecrets(customPatternsFile)
			if err != nil {
				gologger.Error().Msgf("Failed to load custom patterns: %v", err)
				secretMatchResult = scanner.SecretsMatch(Source, Data)
			} else {
				secretMatchResult = scanner.SecretsMatchWithCustom(Source, Data, customSecrets)
			}
		} else {
			secretMatchResult = scanner.SecretsMatch(Source, Data)
		}
	}

	if wantURLs || wantEndpoints {
		endpointMatchResult := scanner.EndpointsMatch(Data, FilterExtension)
		for _, v := range endpointMatchResult {
			if len(v) >= 4 && v[:4] == "http" || len(v) >= 5 && v[:5] == "https" {
				if !strings.Contains(v, "w3.org") {
					if wantURLs {
						sortedUrls = append(sortedUrls, v)
					}
					continue
				}
			} else {
				if wantEndpoints {
					sortedEndpoints = append(sortedEndpoints, v)
				}
			}
		}
	}

	return secretMatchResult, sortedUrls, sortedEndpoints
}

func handleResults(extractEndpoints, extractURLs, extractSecrets bool, secrets []scanner.SecretMatched, urls, endpoints []string, input string, outputFile *os.File, colorize bool) {
	if extractSecrets {
		handleSecret(secrets, input, outputFile, colorize)
	}
	if extractURLs {
		handleURL(urls, input, outputFile, colorize)
	}
	if extractEndpoints {
		handleEndpoint(endpoints, input, outputFile, colorize)
	}
}

func handleSecret(secrets []scanner.SecretMatched, input string, outputFile *os.File, colorize bool) {
	if len(secrets) > 0 {
		if colorize {
			fmt.Printf("[%s] Secrets %s\n", aurora.Blue("INF"), input)
		} else {
			fmt.Printf("[INF] Secrets %s\n", input)
		}

		for _, secret := range secrets {
			var result string
			if colorize {
				result = fmt.Sprintf("%s: %s\n%s: %s\n\n", aurora.Green("Name"), secret.Secret.Name, aurora.Green("Match"), secret.Match)
			} else {
				result = fmt.Sprintf("Name: %s\nMatch: %s\n\n", secret.Secret.Name, secret.Match)
			}
			fmt.Print(result)

			if outputFile != nil {
				fmt.Fprintf(outputFile, "Source: %s\nName: %s\nMatch: %s\n\n", input, secret.Secret.Name, secret.Match)
			}
		}
	}
}

func handleEndpoint(endpoints []string, input string, outputFile *os.File, colorize bool) {
	if len(endpoints) > 0 {
		if colorize {
			fmt.Printf("[%s] Endpoints %s\n", aurora.Blue("INF"), input)
		} else {
			fmt.Printf("[INF] Endpoints %s\n", input)
		}

		for _, endpoint := range endpoints {
			fmt.Println(endpoint)

			if outputFile != nil {
				fmt.Fprintf(outputFile, "Source: %s\nEndpoint: %s\n\n", input, endpoint)
			}
		}
		fmt.Println("")
	}
}

func handleURL(urls []string, input string, outputFile *os.File, colorize bool) {
	if len(urls) > 0 {
		if colorize {
			fmt.Printf("[%s] URLs %s\n", aurora.Blue("INF"), input)
		} else {
			fmt.Printf("[INF] URLs %s\n", input)
		}

		for _, URL := range urls {
			fmt.Println(URL)

			if outputFile != nil {
				fmt.Fprintf(outputFile, "Source: %s\nURL: %s\n\n", input, URL)
			}
		}
		fmt.Println("")
	}
}

func parseURL(url string) (*urlutil.URL, error) {
	urlx, err := urlutil.ParseURL(url, true)
	if err != nil {
		gologger.Debug().Msgf("Failed to parse url %v got %v", url, err)
	}
	return urlx, err
}

func request(URL string, Header string, timeout int) ([]byte, error) {
	u, _ := parseURL(URL)

	if u.Host == "" {
		return nil, fmt.Errorf("%s", "domain is not valid")
	}

	if u.Scheme == "" {
		URL = "https://" + u.Host
	}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true,
			},
			MaxIdleConnsPerHost: 100,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Allows redirects to be followed
		},
	}

	req, err := http.NewRequest("GET", URL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Firefox/120.0")
	req.Header.Set("Accept", "*/*")

	if Header != "" {
		headers := strings.SplitN(Header, ":", 2)
		if len(headers) == 2 {
			req.Header.Set(strings.TrimSpace(headers[0]), strings.TrimSpace(headers[1]))
		} else {
			return nil, fmt.Errorf("custom header is not valid. Example: 'X-header: Value'")
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code is not 200: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func printUsage() {
	gologger.Print().Msgf("Extractify - A tool for extracting endpoints, URLs, and secrets from various sources\n")

	gologger.Print().Msgf("\nInput Flags:")
	gologger.Print().Msgf("\t-url,      -u       URL for scanning")
	gologger.Print().Msgf("\t-list,     -l       List of URLs for scanning")
	gologger.Print().Msgf("\t-file,     -f       Local file or directory for scanning")
	gologger.Print().Msgf("\tOr list of urls from stdin")

	gologger.Print().Msgf("\nExtract Types:")
	gologger.Print().Msgf("\t-endpoints, -ee      Include endpoints (combine with -eu/-es as needed)")
	gologger.Print().Msgf("\t-urls,      -eu      Include URLs (combine with -ee/-es as needed)")
	gologger.Print().Msgf("\t-secrets,   -es      Include secrets (combine with -ee/-eu as needed)")
	gologger.Print().Msgf("\t-all,       -ea      Extract all types")
	gologger.Print().Msgf("\t(no -ee/-eu/-es)     Extract all types (default)")

	gologger.Print().Msgf("\nOther Options:")
	gologger.Print().Msgf("\t-header,          	-H     Set custom header (e.g., 'Authorization: Bearer token')")
	gologger.Print().Msgf("\t-concurrent,      	-c     Number of concurrent workers [default: 10]")
	gologger.Print().Msgf("\t-timeout,         	-t     Timeout in seconds for HTTP requests [default: 20]")
	gologger.Print().Msgf("\t-output,          	-o     Write JSON results to file")
	gologger.Print().Msgf("\t-json,            	-j     JSON to stdout if no -o; with -o, JSON file only (no human console)")
	gologger.Print().Msgf("\t-dedup                  Deduplicate URLs, endpoints, and secrets across sources (first file wins)")
	gologger.Print().Msgf("\t-patterns,        	-p     Custom regex patterns file")
	gologger.Print().Msgf("\t-version,         	-V     Show version information")
	gologger.Print().Msgf("\t-no-color,        	-nc    Disable colorized output")
	gologger.Print().Msgf("\t-filter-extension, -fe   Filter extensions in endpoint results (comma-separated)")

	gologger.Print().Msgf("\nExamples:")
	gologger.Print().Msgf("\textractify -u https://example.com")
	gologger.Print().Msgf("\textractify -l urls.txt -es -o results.txt")
	gologger.Print().Msgf("\textractify -f javascript_files/ -ea")
	gologger.Print().Msgf("\tcat urls.txt | extractify -ea -c 20")
}
