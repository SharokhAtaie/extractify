package main

import (
	"crypto/tls"
	"fmt"
	"github.com/SharokhAtaie/extractify/scanner"
	"github.com/go-resty/resty/v2"
	"github.com/logrusorgru/aurora/v4"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	sUtils "github.com/projectdiscovery/utils/slice"
	urlutil "github.com/projectdiscovery/utils/url"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type options struct {
	file      string
	url       string
	list      string
	endpoint  bool
	secret    bool
	parameter bool
	all       bool
	urls      bool
	header    string
	filterExt goflags.StringSlice
	verbose   bool
}

func main() {
	opt := &options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("A tool for extract Endpoints, URLs, Parameters and Secrets from contents")

	flagSet.CreateGroup("Inputs", "Inputs",
		flagSet.StringVarP(&opt.url, "url", "u", "", "URL for scanning"),
		flagSet.StringVarP(&opt.list, "list", "l", "", "List of URLs for scanning"),
		flagSet.StringVarP(&opt.file, "file", "f", "", "Local file data for scanning"),
	)

	flagSet.CreateGroup("Extract", "Extracts",
		flagSet.BoolVarP(&opt.endpoint, "endpoints", "ee", false, "Extract endpoints"),
		flagSet.BoolVarP(&opt.urls, "urls", "eu", false, "Extract urls"),
		flagSet.BoolVarP(&opt.parameter, "parameters", "ep", false, "Extract parameters"),
		flagSet.BoolVarP(&opt.secret, "secrets", "es", false, "Extract secrets"),
		flagSet.BoolVarP(&opt.all, "all", "ea", false, "Extract all"),
	)

	flagSet.CreateGroup("Others", "Others",
		flagSet.StringSliceVarP(&opt.filterExt, "filter-extension", "fe", []string{"svg", "png", "jpg", "jpeg"}, "list of extensions svg,png (comma-separated)", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&opt.header, "header", "H", "", "Set custom header"),
		flagSet.BoolVarP(&opt.verbose, "verbose", "v", false, "Verbose mode"),
	)

	if err := flagSet.Parse(); err != nil {
		log.Fatalf("Could not parse flags: %s\n", err)
	}

	if opt.url == "" && opt.list == "" && opt.file == "" && !fileutil.HasStdin() {
		PrintUsage()
		return
	}

	if opt.file != "" {
		bin, err := os.ReadFile(opt.file)
		if err != nil {
			gologger.Error().Msgf("failed to read file %v got %v", opt.list, err)
		}

		gologger.Info().Msgf("Processing %s", opt.file)
		secrets, urls, endpoints, parameters := Run(bin, opt.file, opt.filterExt)

		HandleResults(opt.endpoint, opt.parameter, opt.urls, opt.secret, opt.all, secrets, urls, endpoints, parameters, opt.file)
		return
	}

	var URLs []string

	URLs = append(URLs, opt.url)

	if fileutil.FileExists(opt.list) {
		bin, err := os.ReadFile(opt.list)
		if err != nil {
			gologger.Error().Msgf("failed to read file %v got %v", opt.list, err)
		}
		URLs = strings.Fields(string(bin))
	}

	if fileutil.HasStdin() {
		bin, err := io.ReadAll(os.Stdin)
		if err != nil {
			gologger.Error().Msgf("failed to read file %v got %v", opt.list, err)
		}

		URLs = strings.Fields(string(bin))
	}

	for _, url := range URLs {

		Data, err := Request(url, opt.header, opt.verbose)
		if err != nil {
			gologger.Error().Msgf("%s [%s]\n\n", err, url)
			continue
		}

		secrets, urls, endpoints, parameters := Run(Data, url, opt.filterExt)

		HandleResults(opt.endpoint, opt.parameter, opt.urls, opt.secret, opt.all, secrets, urls, endpoints, parameters, url)
	}
}

func Run(Data []byte, Source string, FilterExtension []string) ([]scanner.SecretMatched, []string, []string, []string) {
	var sortedUrls []string
	var sortedEndpoints []string

	SecretMatchResult := scanner.SecretsMatch(Source, Data)

	EndpointMatchResult := scanner.EndpointsMatch(Data, FilterExtension)

	for _, v := range EndpointMatchResult {
		if len(v) >= 4 && v[:4] == "http" || len(v) >= 5 && v[:5] == "https" {
			sortedUrls = append(sortedUrls, v)
			continue
		} else {
			sortedEndpoints = append(sortedEndpoints, v)
		}
	}

	ParameterMatchResults := scanner.ParameterMatch(string(Data))

	return SecretMatchResult, sortedUrls, sortedEndpoints, sUtils.Dedupe(ParameterMatchResults)
}

func HandleResults(endpoint, parameter, url, secret, all bool, secrets []scanner.SecretMatched, urls, endpoints, parameters []string, input string) {
	if all {
		HandleSecret(secrets, input)
		HandleURL(urls, input)
		HandleEndpoint(endpoints, input)
		HandleParameter(parameters, input)
		return
	}

	if endpoint {
		HandleEndpoint(endpoints, input)
	}

	if parameter {
		HandleParameter(parameters, input)
	}

	if url {
		HandleURL(urls, input)
	}

	if secret {
		HandleSecret(secrets, input)
	}

	if !endpoint && !parameter && !url && !secret && !all {
		HandleSecret(secrets, input)
	}
}

func HandleSecret(secrets []scanner.SecretMatched, input string) {
	if len(secrets) > 0 {
		fmt.Printf("[%s] Secrets %s\n", aurora.Blue("INF"), input)
		for _, secret := range secrets {
			fmt.Printf("%s: %s\n%s: %s\n\n", aurora.Green("Name"), secret.Secret.Name, aurora.Green("Match"), secret.Match)
		}
	} else {
		gologger.Info().Msgf("%s \nNo results for Secrets\n\n", input)
	}
}

func HandleEndpoint(endpoints []string, input string) {
	if len(endpoints) > 0 {
		fmt.Printf("[%s] Endpoints %s\n", aurora.Blue("INF"), input)
		for _, endpoint := range endpoints {
			fmt.Println(endpoint)
		}
		fmt.Println("")
	} else {
		gologger.Info().Msgf("%s \nNo results for Endpoints\n\n", input)
	}
}

func HandleURL(urls []string, input string) {
	if len(urls) > 0 {
		fmt.Printf("[%s] URLs %s\n", aurora.Blue("INF"), input)
		for _, URL := range urls {
			fmt.Println(URL)
		}
		fmt.Println("")
	} else {
		gologger.Info().Msgf("%s \nNo results for URLs\n\n", input)
	}
}

func HandleParameter(parameters []string, input string) {
	if len(parameters) > 0 {
		fmt.Printf("[%s] Parameters %s\n", aurora.Blue("INF"), input)
		for _, param := range parameters {
			fmt.Println(param)
		}
		fmt.Println("")
	} else {
		gologger.Info().Msgf("%s \nNo results for Parameters\n\n", input)
	}
}

func ParseURL(url string) (*urlutil.URL, error) {
	urlx, err := urlutil.ParseURL(url, true)
	if err != nil {
		gologger.Debug().Msgf("failed to parse url %v got %v", url, err)
	}
	return urlx, err
}

func Request(URL string, Header string, Verbose bool) ([]byte, error) {

	u, _ := ParseURL(URL)

	if u.Host == "" {
		return nil, fmt.Errorf("%s", "Domain is not valid")
	}

	if u.Scheme == "" {
		URL = "https://" + u.Host
	}

	client := resty.New().
		SetTimeout(2*time.Second).
		SetHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Firefox/120.0").
		SetHeader("Accept", "*/*").
		SetHeader("Origin", u.Scheme+"://"+u.Host).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetRedirectPolicy(resty.RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}))

	if Header != "" {
		headers := strings.Split(Header, ":")
		if len(headers) == 2 {
			client.SetHeader(headers[0], strings.TrimSpace(headers[1]))
		} else {
			gologger.Fatal().Msgf("Custom header is not valid. Example (\"X-header: Value\")")
		}
	}

	if Verbose {
		client.SetDebug(true)
	}

	resp, err := client.R().
		Get(URL)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("status code is not 200: %d", resp.StatusCode())
	}

	return resp.Body(), nil
}

func PrintUsage() {
	gologger.Print().Msgf("Input Flags:\n")
	gologger.Print().Msgf("\t-url,      -u       URL for scanning")
	gologger.Print().Msgf("\t-list,     -l       List of URLs for scanning")
	gologger.Print().Msgf("\t-file,     -f       Local file data for scanning")
	gologger.Print().Msgf("\tOr list of urls from stdin")
}
