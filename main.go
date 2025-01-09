package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

func main() {
	// Command-line arguments
	domain := flag.String("d", "", "Specify the domain to enumerate subdomains.")
	outputFile := flag.String("o", "subdomains.txt", "Specify the output file to save results.")
	domainFile := flag.String("f", "", "Specify a file containing a list of domains to process.")
	flag.Parse()

	// Validate input
	if *domain == "" && *domainFile == "" {
		fmt.Println("Usage: -d <domain> or -f <file_with_domains>")
		os.Exit(1)
	}

	// Load domains
	var domains []string
	if *domainFile != "" {
		file, err := os.Open(*domainFile)
		if err != nil {
			fmt.Printf("Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			domains = append(domains, scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading file: %v\n", err)
			os.Exit(1)
		}
	} else {
		domains = append(domains, *domain)
	}

	// Process domains concurrently
	var wg sync.WaitGroup
	results := make(chan string, len(domains)*10)

	for _, d := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			processDomain(domain, results)
		}(d)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	saveResults(results, *outputFile)
}

// processDomain queries APIs to enumerate subdomains for a given domain.
func processDomain(domain string, results chan string) {
	apis := []string{
		fmt.Sprintf("https://dns.bufferover.run/dns?q=.%s", domain),
		fmt.Sprintf("https://riddler.io/search/exportcsv?q=pld:%s", domain),
		fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain),
		fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey", domain),
		fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain),
		fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain),
		fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", domain),
		fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=100&page=1", domain),
		fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain),
	}

	// Use a set-like map to deduplicate subdomains
	subdomains := make(map[string]struct{})

	for _, api := range apis {
		resp, err := http.Get(api)
		if err != nil {
			fmt.Printf("Error querying API %s: %v\n", api, err)
			continue
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Error reading response from %s: %v\n", api, err)
			continue
		}

		// Extract subdomains using regex or JSON parsing
		if strings.Contains(api, "crt.sh") || strings.Contains(api, "certspotter") || strings.Contains(api, "bufferover") {
			extractSubdomainsFromJSON(body, domain, subdomains)
		} else {
			extractSubdomainsFromText(body, domain, subdomains)
		}
	}

	// Send results to channel
	for subdomain := range subdomains {
		results <- subdomain
	}
}

// extractSubdomainsFromJSON parses JSON responses and extracts subdomains.
func extractSubdomainsFromJSON(body []byte, domain string, subdomains map[string]struct{}) {
	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		return
	}

	// Traverse JSON structure to find subdomains
	switch v := data.(type) {
	case []interface{}:
		for _, item := range v {
			switch sub := item.(type) {
			case string:
				if strings.Contains(sub, domain) {
					subdomains[sub] = struct{}{}
				}
			case []interface{}:
				for _, nested := range sub {
					if nestedStr, ok := nested.(string); ok && strings.Contains(nestedStr, domain) {
						subdomains[nestedStr] = struct{}{}
					}
				}
			}
		}
	case map[string]interface{}:
		for _, value := range v {
			if sub, ok := value.(string); ok && strings.Contains(sub, domain) {
				subdomains[sub] = struct{}{}
			}
		}
	}
}

// extractSubdomainsFromText parses plain text and extracts subdomains using regex.
func extractSubdomainsFromText(body []byte, domain string, subdomains map[string]struct{}) {
	re := regexp.MustCompile(`([\w.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	for _, match := range matches {
		subdomains[match] = struct{}{}
	}
}

// saveResults writes results to the specified output file.
func saveResults(results chan string, outputFile string) {
	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	subdomains := make([]string, 0)
	for result := range results {
		subdomains = append(subdomains, result)
	}

	// Sort and deduplicate results
	sort.Strings(subdomains)
	for _, subdomain := range subdomains {
		fmt.Fprintln(writer, subdomain)
	}
}
