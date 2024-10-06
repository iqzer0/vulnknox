package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"text/tabwriter"
)

const version = "1.0.0"

type Configuration struct {
	APIURL, APIKey, DiscordWebhook string
}

type KnoxssResponse struct {
	XSS       string `json:"XSS"`
	PoC       string `json:"PoC"`
	Error     string `json:"Error"`
	APICall   string `json:"API Call"`
	POSTData  string `json:"POST Data"`
	Timestamp string `json:"Timestamp"`
}

var (
	config       Configuration
	configPath   string
	outFile      *os.File
	latestAPICallBalance string

	successCount int
	errorCount   int
	safeCount    int
	requestCount int
	skipCount    int
	blockedDomains = make(map[string]int)

	mutex sync.Mutex
	bannerPrinted bool

	verbose     bool
	skipBlocked int
)

func main() {
	var (
		apiKey, inputURL, inputFile, outputFile, httpMethod, postData, headers, discordWebhook, proxyURL string
		outputOverwrite, outputAll, afb, checkPoC, flashMode, successOnly, verboseFlag, showVersion, suppressBanner bool
		processes, timeout, retries, retryInterval, skipBlockedFlag int
	)
	flag.StringVar(&apiKey, "api-key", "", "KNOXSS API Key (overrides config file)")
	flag.StringVar(&inputURL, "u", "", "Input URL to send to KNOXSS API")
	flag.StringVar(&inputFile, "i", "", "Input file containing URLs to send to KNOXSS API")
	flag.StringVar(&outputFile, "o", "", "The file to save the results to")
	flag.BoolVar(&outputOverwrite, "ow", false, "Overwrite output file if it exists")
	flag.BoolVar(&outputAll, "oa", false, "Output all results to file, not just successful ones")
	flag.StringVar(&httpMethod, "X", "GET", "HTTP method to use: GET, POST, or BOTH")
	flag.StringVar(&postData, "pd", "", "POST data in format 'param1=value&param2=value'")
	flag.StringVar(&headers, "headers", "", "Custom headers in format 'Header1:value1,Header2:value2'")
	flag.BoolVar(&afb, "afb", false, "Use Advanced Filter Bypass")
	flag.BoolVar(&checkPoC, "checkpoc", false, "Enable CheckPoC feature")
	flag.BoolVar(&flashMode, "flash", false, "Enable Flash Mode")
	flag.BoolVar(&successOnly, "s", false, "Only show successful XSS payloads in output")
	flag.IntVar(&processes, "p", 3, "Number of parallel processes (1-5)")
	flag.IntVar(&timeout, "t", 600, "Timeout for API requests in seconds")
	flag.StringVar(&discordWebhook, "dw", "", "Discord Webhook URL (overrides config file)")
	flag.IntVar(&retries, "r", 3, "Number of retries for failed requests")
	flag.IntVar(&retryInterval, "ri", 30, "Interval between retries in seconds")
	flag.IntVar(&skipBlockedFlag, "sb", 0, "Skip domains after this many 403 responses")
	flag.StringVar(&proxyURL, "proxy", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	flag.BoolVar(&verboseFlag, "v", false, "Verbose output")
	flag.BoolVar(&showVersion, "version", false, "Show version number")
	flag.BoolVar(&suppressBanner, "no-banner", false, "Suppress the banner")

	flag.Usage = func() {
		printBannerOnce(&bannerPrinted, suppressBanner)
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		w := tabwriter.NewWriter(os.Stderr, 0, 0, 2, ' ', 0)
		flagsInOrder := []string{
			"u", "i", "X", "pd", "headers", "afb", "checkpoc", "flash",
			"o", "ow", "oa", "s", "p", "t", "dw", "r", "ri", "sb",
			"proxy", "v", "version", "no-banner", "api-key",
		}
	
		for _, name := range flagsInOrder {
			f := flag.Lookup(name)
			if f == nil {
				continue
			}
			var defaultValue string
			if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "true" {
				defaultValue = fmt.Sprintf(" %s", f.DefValue)
			}
			fmt.Fprintf(w, "  -%s%s\t%s\n", f.Name, defaultValue, f.Usage)
		}
		w.Flush()
		fmt.Fprintf(os.Stderr, "\n")
	}

	flag.Parse()

	verbose = verboseFlag
	skipBlocked = skipBlockedFlag

	if showVersion {
		fmt.Printf("VulnKnox version %s\n", version)
		os.Exit(0)
	}

	printBannerOnce(&bannerPrinted, suppressBanner)

	loadConfig(apiKey)

	if discordWebhook != "" {
		config.DiscordWebhook = discordWebhook
	}

	urls := getInputURLs(inputURL, inputFile)
	if len(urls) == 0 {
		fmt.Println("\033[31mError: No input provided. Use -u, -i, or pipe URLs.\033[0m")
		flag.Usage()
		os.Exit(1)
	}

	if outputFile != "" {
		var err error
		if outputOverwrite {
			outFile, err = os.Create(outputFile)
		} else {
			outFile, err = os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		}
		if err != nil {
			log.Fatalf("Error opening output file: %v", err)
		}
		defer outFile.Close()
	}

	results := processURLs(urls, httpMethod, postData, headers, afb, checkPoC, flashMode, processes, timeout, retries, retryInterval, proxyURL)

	for _, result := range results {
		outputResult(result, successOnly, outputAll)
	}
	// Update the latest APICall balance
	latestAPICallBalance = getLatestAPICallBalance(results)

	printSummary()
}

func printBannerOnce(printed *bool, suppress bool) {
	if !*printed && !suppress {
		showBanner()
		*printed = true
	}
}

func loadConfig(apiKey string) {
	home, _ := os.UserHomeDir()
	configDir := filepath.Join(home, ".config", "vulnknox")
	if runtime.GOOS == "windows" {
		configDir = filepath.Join(os.Getenv("APPDATA"), "VulnKnox")
	}
	configPath = filepath.Join(configDir, "config.json")

	os.MkdirAll(configDir, 0755)

	defaultConfig := Configuration{
		APIURL: "https://api.knoxss.pro",
		APIKey: "YOUR_API_KEY_HERE",
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configJSON, _ := json.MarshalIndent(defaultConfig, "", "  ")
		ioutil.WriteFile(configPath, configJSON, 0644)
		fmt.Printf("Default config file created at %s\n", configPath)
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		fmt.Printf("Error reading config file: %v\n", err)
		config = defaultConfig
	} else {
		err = json.Unmarshal(data, &config)
		if err != nil {
			fmt.Printf("Error parsing config file: %v\n", err)
			config = defaultConfig
		}
	}

	if config.APIURL == "" {
		config.APIURL = defaultConfig.APIURL
	}

	if apiKey != "" {
		config.APIKey = apiKey
	}

	if config.APIKey == "" || config.APIKey == "YOUR_API_KEY_HERE" {
		fmt.Println("Please provide an API key using the -api-key flag or by editing the config file.")
		fmt.Printf("Config file location: %s\n", configPath)
		os.Exit(1)
	}

	fmt.Printf("Using API URL: %s\n", config.APIURL)
}

func getInputURLs(inputURL, inputFile string) []string {
	if inputURL != "" {
		return []string{inputURL}
	}
	if inputFile != "" {
		file, err := os.Open(inputFile)
		if err != nil {
			log.Fatalf("Error opening input file: %v", err)
		}
		defer file.Close()
		var urls []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			urls = append(urls, scanner.Text())
		}
		return urls
	}
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		var urls []string
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			urls = append(urls, scanner.Text())
		}
		return urls
	}
	fmt.Println("\033[31mError: No input provided. Use -u, -i, or pipe URLs.\033[0m")
	flag.Usage()
	os.Exit(1)
	return nil
}

func processURLs(urls []string, httpMethod, postData, headers string, afb, checkPoC, flashMode bool,
	processes, timeout, retries, retryInterval int, proxyURL string) []KnoxssResponse {

	var results []KnoxssResponse
	sem := make(chan bool, processes)
	var wg sync.WaitGroup
	var mutex sync.Mutex

	for _, u := range urls {
		wg.Add(1)
		sem <- true
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			resList := processURL(u, httpMethod, postData, headers, afb, checkPoC, flashMode,
				timeout, retries, retryInterval, proxyURL)

			mutex.Lock()
			results = append(results, resList...)
			mutex.Unlock()
		}(u)
	}

	wg.Wait()
	return results
}

func processURL(targetURL, httpMethod, postData, headers string, afb, checkPoC, flashMode bool, timeout, retries, retryInterval int, proxyURL string) []KnoxssResponse {
	parsedURL, err := url.ParseRequestURI(targetURL)
	if err != nil {
		escapedURL := escapeURL(targetURL)
		parsedURL, err = url.ParseRequestURI(escapedURL)
		if err != nil {
			return []KnoxssResponse{{Error: fmt.Sprintf("Invalid URL: %v", err)}}
		}
		targetURL = escapedURL
	}

	methods := []string{}
	if httpMethod == "BOTH" {
		methods = []string{"GET", "POST"}
	} else {
		methods = []string{httpMethod}
	}

	var results []KnoxssResponse

	for _, method := range methods {
		domain := fmt.Sprintf("(%s) %s://%s", method, parsedURL.Scheme, parsedURL.Host)
		if skipBlocked > 0 && blockedDomains[domain] >= skipBlocked {
			if verbose {
				fmt.Printf("[VERBOSE] Skipping domain %s after %d 403 responses\n", domain, blockedDomains[domain])
			}
			mutex.Lock()
			skipCount++
			mutex.Unlock()
			results = append(results, KnoxssResponse{Error: fmt.Sprintf("Domain %s skipped due to multiple 403 responses", domain)})
			continue
		}

		result := performRequest(targetURL, method, postData, headers, afb, checkPoC, flashMode,
			timeout, retries, retryInterval, proxyURL, domain)
		results = append(results, result)
	}

	return results
}

func escapeURL(rawURL string) string {
	return url.QueryEscape(rawURL)
}

func performRequest(targetURL, method, postData, headers string, afb, checkPoC, flashMode bool, timeout, retries, retryInterval int, proxyURL, domain string) KnoxssResponse {
	data := url.Values{}

	encodedTargetURL := encodeParams(targetURL)
	encodedPostData := encodeParams(postData)

	if method == "GET" {
		data.Set("target", encodedTargetURL)
	} else if method == "POST" {
		data.Set("target", encodedTargetURL)
		data.Set("post", encodedPostData)
	}

	if afb {
		data.Set("afb", "1")
	}
	if checkPoC {
		data.Set("checkpoc", "1")
	}
	if headers != "" {
		authValue := strings.ReplaceAll(headers, ",", "%0D%0A")
		authValue = encodeParams(authValue)
		data.Set("auth", authValue)
		if verbose {
			fmt.Printf("[VERBOSE] Auth parameter set to: %s\n", authValue)
		}
	}

	if flashMode {
		if method == "GET" {
			data.Set("target", insertXSSMark(data.Get("target")))
		} else if method == "POST" {
			data.Set("post", insertXSSMark(data.Get("post")))
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if proxyURL != "" {
		proxyURLParsed, _ := url.Parse(proxyURL)
		transport.Proxy = http.ProxyURL(proxyURLParsed)
	}

	client := &http.Client{Timeout: time.Duration(timeout) * time.Second, Transport: transport}

	var result KnoxssResponse
	for attempt := 0; attempt <= retries; attempt++ {
		if verbose {
			fmt.Printf("[VERBOSE] Attempt %d for URL: %s\n", attempt+1, targetURL)
		}
		req, err := http.NewRequest("POST", config.APIURL, strings.NewReader(data.Encode()))
		if err != nil {
			result.Error = fmt.Sprintf("Error creating request: %v", err)
			if verbose {
				fmt.Printf("[VERBOSE] %s\n", result.Error)
			}
			time.Sleep(time.Duration(retryInterval) * time.Second)
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-API-KEY", config.APIKey)

		if verbose {
			fmt.Printf("[VERBOSE] Sending request to KNOXSS API for URL: %s\n", targetURL)
			fmt.Printf("[VERBOSE] Method: %s\n", method)
			if method == "POST" {
				fmt.Printf("[VERBOSE] POST data: %s\n", postData)
			}
			if headers != "" {
				fmt.Printf("[VERBOSE] Custom headers: %s\n", headers)
			}
			fmt.Printf("[VERBOSE] Data sent to API: %s\n", data.Encode())
		}

		resp, err := client.Do(req)
		if err != nil {
			result.Error = fmt.Sprintf("Error sending request: %v", err)
			if verbose {
				fmt.Printf("[VERBOSE] %s\n", result.Error)
			}
			time.Sleep(time.Duration(retryInterval) * time.Second)
			continue
		}
		defer resp.Body.Close()

		body, _ := ioutil.ReadAll(resp.Body)
		json.Unmarshal(body, &result)

		if verbose {
			fmt.Printf("[VERBOSE] Received response from KNOXSS API for URL: %s\n", targetURL)
			fmt.Printf("[VERBOSE] Status code: %d\n", resp.StatusCode)
			fmt.Printf("[VERBOSE] Response body: %s\n", string(body))
		}

		if resp.StatusCode == 403 {
			mutex.Lock()
			blockedDomains[domain]++
			mutex.Unlock()
			if verbose {
				fmt.Printf("[VERBOSE] Received 403 from %s. Incremented blocked count to %d\n", domain, blockedDomains[domain])
			}
		}

		if result.Error == "" || result.Error == "none" {
			break
		}

		time.Sleep(time.Duration(retryInterval) * time.Second)
	}

	return result
}

func getLatestAPICallBalance(results []KnoxssResponse) string {
	var latestTime time.Time
	var latestBalance string
	for _, result := range results {
		if result.Timestamp != "" && result.APICall != "" {
			resultTime, err := time.Parse(time.RFC1123Z, result.Timestamp)
			if err == nil {
				if resultTime.After(latestTime) {
					latestTime = resultTime
					latestBalance = result.APICall
				}
			}
		}
	}
	return latestBalance
}

func outputResult(result KnoxssResponse, successOnly, outputAll bool) {
	mutex.Lock()
	requestCount++
	mutex.Unlock()
	if result.XSS == "true" {
		mutex.Lock()
		successCount++
		mutex.Unlock()
		fmt.Printf("\033[32m[ XSS! ] - %s\033[0m\n", result.PoC)
		if outFile != nil {
			fmt.Fprintf(outFile, "[ XSS! ] - %s\n", result.PoC)
		}
		if config.DiscordWebhook != "" {
			sendDiscordNotification(result.PoC)
		}
	} else if result.Error != "" && result.Error != "none" {
		mutex.Lock()
		errorCount++
		mutex.Unlock()
		if !successOnly {
			fmt.Printf("\033[31m[ ERR! ] - %s\033[0m\n", result.Error)
			if outFile != nil && outputAll {
				fmt.Fprintf(outFile, "[ ERR! ] - %s\n", result.Error)
			}
		}
	} else {
		mutex.Lock()
		safeCount++
		mutex.Unlock()
		if !successOnly {
			fmt.Printf("\033[33m[ SAFE ] - %s\033[0m\n", result.PoC)
			if outFile != nil && outputAll {
				fmt.Fprintf(outFile, "[ SAFE ] - %s\n", result.PoC)
			}
		}
	}
}

func sendDiscordNotification(poc string) {
	webhookURL := config.DiscordWebhook
	if webhookURL == "" {
		return
	}
	payload := map[string]string{"content": poc}
	payloadBytes, _ := json.Marshal(payload)
	http.Post(webhookURL, "application/json", bytes.NewBuffer(payloadBytes))
}

func printSummary() {
	fmt.Printf("\nRequests made to KNOXSS API: %d (XSS!: %d, SAFE: %d, ERR!: %d, SKIP: %d", requestCount, successCount, safeCount, errorCount, skipCount)

	if latestAPICallBalance != "" {
		fmt.Printf(", BALANCE: %s", latestAPICallBalance)
	}
	fmt.Println(")")

	if successCount > 0 {
		fmt.Printf("\033[32m%d successful XSS found!\033[0m\n", successCount)
	} else {
		fmt.Printf("\033[36mNo successful XSS found... better luck next time!\033[0m\n")
	}
}

func showBanner() {
    cyan := "\033[36m"
    red := "\033[31m"
    yellow := "\033[33m"
    green := "\033[32m"
    blue := "\033[34m"
    reset := "\033[0m"

    banner := fmt.Sprintf(`
%s o  %s o       %s o      %s o %s o          o   o %s
%s |  %s |       %s |      %s | /            \ /  %s
%s o   o %s o  o %s | o-o  %s OO   o-o %s o-o   O   %s
%s  \ /  %s |  | %s | | |  %s | \  | | %s | |  / \  %s
%s   o   %s o--o %s o o o  %s o  o o o %s o-o o   o %s`,
        cyan, yellow, green, red, blue, reset,
        cyan, yellow, green, red, reset,
        cyan, yellow, green, red, blue, reset,
        cyan, yellow, green, red, blue, reset,
        cyan, yellow, green, red, blue, reset)

    fmt.Printf("%s%s%s\n", cyan, banner, reset)
    fmt.Printf("%s%sKNOXSS API%s Wrapper in Go %s| Version %s%s\n", cyan, red, yellow, cyan, yellow, version)
    fmt.Printf("%sCredits: %s@KN0X55%s, %s@BruteLogic%s, %s@xnl_h4ck3r%s\n\n", cyan, red, reset, yellow, reset, green, reset)
}

func encodeParams(input string) string {
	return strings.ReplaceAll(input, "&", "%26")
}

func encodeTargetURL(targetURL string) string {
	idx := strings.Index(targetURL, "?")
	if idx == -1 {
		return targetURL
	}
	baseURL := targetURL[:idx+1]
	queryString := targetURL[idx+1:]
	encodedQueryString := strings.ReplaceAll(queryString, "&", "%26")
	return baseURL + encodedQueryString
}

func insertXSSMark(input string) string {
	if strings.Contains(input, "[XSS]") {
		return input
	}
	if strings.Contains(input, "=") {
		return strings.Replace(input, "=", "=[XSS]", 1)
	}
	return input + "[XSS]"
}