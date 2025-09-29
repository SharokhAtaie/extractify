package scanner

import (
	"regexp"
	"strings"

	"github.com/projectdiscovery/gologger"
)

// EndpointsMatch extracts endpoints from byte data based on regex patterns
func EndpointsMatch(Body []byte, FilterExtensions []string) []string {

	// Regex adapted from LinkFinder with added support for ${...} templates and readable structure
	parts := []string{
		// Opening delimiter (a quote/backtick or newline boundary), then start of main capture group
		"(?:[`\"'\\n\\r])(",

		// 1) Absolute URLs (optionally templated with ${...}) including protocol or protocol-relative
		"((?:\\$\\{[^\\}]+\\})?(?:[a-zA-Z]{1,10}:\\/\\/|\\/\\/)[^\\s\"'\\/]{1,}\\.[a-zA-Z]{2,}[^\\s\"']{0,})",
		"|",

		// 2) Relative paths (optionally templated with ${...}): /, ../, ./ followed by a path-like segment
		"((?:\\$\\{[^\\}]+\\})?(?:\\/|\\.\\.\\/|\\.\\/)[^\\s\"'><,;| *()(%%$^\\/\\\\\\[\\]][^\\s\"'><,;|()]{1,})",
		"|",

		// 3) File with extension and optional query or trailing slash segment
		"([a-zA-Z0-9_\\-\\/]{1,}\\/[a-zA-Z0-9_\\-\\/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|\\/][^\\s|^\"|']{0,}|))",
		"|",

		// 4) Bare filenames with interesting extensions and optional query
		"([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|cfm|pl|jsp|json|js|action|html|htm|bak|do|txt|xml|xls|xlsx|key|env|pem|git|ovpn|log|secret|secrets|access|dat|db|sql|pwd|passwd|gitignore|properties|dtd|conf|cfg|config|configs|apk|cgi|sh|py|java|rb|rs|go|yml|yaml|toml|php4|zip|tar|tar.bz2|tar.gz|rar|7z|gz|dochtml|doc|docx|csv|odt|ts|phtml|php5|pdf)(?:\\?[^\\s|^\"|^']{0,}|))",
		"|",

		// 5) Path-like segments with optional query and/or hash
		"((?:[a-zA-Z0-9_\\-]+\\/)+[a-zA-Z0-9_\\-]+(?:\\?[^\\s\"'#]*)?(?:#[^\\s\"']*)?)",

		// Closing delimiter
		")(?:[`\"'\\n\\r])",
	}
	regexPattern := strings.Join(parts, "")

	// Exclude pure MIME type matches from results
	excludeMimeTypeRule := strings.Join([]string{
		`MM/YY|DD/MM/YYYY|N/A|`,
		`application/x-www-form-urlencoded|multipart/form-data|multipart/mixed|multipart/alternative|`,
		`text/css|text/plain|text/html|text/xml|text/csv|text/markdown|text/babel|text/tsx|text/jsx|text/x-yaml|text/yaml|`,
		`image/jpeg|image/jpg|image/png|image/svg+xml|image/gif|image/tiff|image/webp|image/bmp|image/x-icon|image/vnd.microsoft.icon|image/heic|image/heif|`,
		`audio/mpeg|audio/wav|audio/webm|audio/aac|audio/ogg|audio/flac|`,
		`video/mp4|video/mpeg|video/webm|video/ogg|video/mp2t|video/x-msvideo|video/quicktime|`,
		`font/ttf|font/woff|font/woff2|font/x-woff2|font/x-woff|font/otf|application/font-woff|application/font-woff2|`,
		`application/octet-stream|binary/octet-stream|application/pdf|application/xml|application/rss+xml|application/atom+xml|`,
		`application/json|application/ld+json|application/manifest+json|application/x-ndjson|application/graphql|`,
		`application/x-font-ttf|application/x-font-otf|application/x-sh|application/x-shellscript|application/x-httpd-php|application/x-perl|`,
		`application/javascript|application/typescript|application/x-typescript|text/x-handlebars-template|text/x-gfm|`,
		`application/zip|application/gzip|application/x-gzip|application/x-tar|application/x-bzip2|application/x-7z-compressed|application/x-rar-compressed|`,
		`application/vnd.android.package-archive|application/msword|application/vnd.openxmlformats-officedocument.wordprocessingml.document|`,
		`application/vnd.ms-excel|application/vnd.openxmlformats-officedocument.spreadsheetml.sheet|`,
		`application/vnd.ms-powerpoint|application/vnd.openxmlformats-officedocument.presentationml.presentation`,
	}, "")
	excludeMimeTypeRe := regexp.MustCompile("^(?:" + excludeMimeTypeRule + ")$")

	// Compile the regular expression
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		gologger.Fatal().Msgf("Error compiling regex: %s", err)
	}

	matches := re.FindAllString(string(Body), -1)

	var cleanedMatches []string
	seenLines := make(map[string]bool)

	for _, match := range matches {
		// Ensure the length of match is sufficient
		if len(match) > 2 {
			// Extract the inner value without surrounding delimiter
			cleanedMatch := match[1 : len(match)-1]

			// Skip pure MIME type strings
			if excludeMimeTypeRe.MatchString(cleanedMatch) {
				continue
			}

			if strings.HasPrefix(cleanedMatch, "//") {
				continue
			}

			// Check if the cleanedMatch has an excluded extension
			include := true
			for _, ext := range FilterExtensions {
				if strings.HasSuffix(cleanedMatch, "."+ext) {
					include = false
					break
				}
			}

			// Check for duplicates
			if include && !seenLines[cleanedMatch] {
				cleanedMatches = append(cleanedMatches, cleanedMatch)
				seenLines[cleanedMatch] = true
			}
		}
	}

	return cleanedMatches
}
