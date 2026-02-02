package scanner

import (
	"regexp"
	"strings"

	"github.com/projectdiscovery/gologger"
)

// EndpointsMatch extracts endpoints from byte data based on regex patterns
func EndpointsMatch(Body []byte, FilterExtensions []string) []string {

	// Comprehensive regex pattern - captures URLs, endpoints, and file paths ONLY when inside quotes
	parts := []string{
		// Opening context - path must be inside a quoted string (after ' " or `)
		`(?:['` + "`" + `"]\s*|[=:]\s*['` + "`" + `"]|[,\[\{]\s*['` + "`" + `"])`,
		// Start main capture group
		`(`,

		// 1) Full URLs with protocol (http, https, ftp, wss, etc.)
		`[a-zA-Z][a-zA-Z0-9+.-]*://[^'` + "`" + `"]+(?:\?[^'` + "`" + `"]*)?(?:#[^'` + "`" + `"]*)?`,
		`|`,

		// 2) Absolute paths starting with / (including template variables)
		`/(?:\$\{[^}]+\}|[a-zA-Z0-9_.-])[^'` + "`" + `"]*`,
		`|`,

		// 3) Relative paths starting with ./ or ../
		`\.\.?/[^'` + "`" + `"]+`,
		`|`,

		// 4) API-like paths (word/word structure) - only when quoted or after assignment
		`[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_${}.-]+)+(?:\?[^'` + "`" + `"]*)?(?:#[^'` + "`" + `"]*)?`,
		`|`,

		// 5) Files with interesting extensions - only when quoted or after assignment
		// \b after extension ensures we don't match obj.access when the full identifier is obj.accessToken (RE2 has no lookahead)
		`[a-zA-Z0-9_-]+\.(?:php|asp|aspx|cfm|pl|jsp|json|js|action|html|htm|bak|do|txt|xml|xls|xlsx|key|env|pem|git|ovpn|log|secret|secrets|access|dat|db|sql|pwd|passwd|gitignore|properties|dtd|conf|cfg|config|configs|apk|cgi|sh|py|java|rb|rs|go|yml|yaml|toml|php4|zip|tar|gz|rar|7z|dochtml|doc|docx|csv|odt|ts|phtml|php5|pdf|vue|svelte|jsx|tsx|scss|sass|less|styl|wasm|dll|exe|bin|iso|dmg|pkg|deb|rpm|msi)\b(?:\?[^'` + "`" + `"]*)?`,
		`|`,

		// 6) Template literal paths with variables
		`\$\{[^}]+\}/[^'` + "`" + `"]*`,
		`|`,

		// 7) Protocol-relative URLs
		`//[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})?(?::[0-9]+)?(?:/[^'` + "`" + `"]*)?`,

		// End capture group
		`)`,
	}

	regexPattern := strings.Join(parts, "")

	// Exclude pure MIME type matches from results
	excludeMimeTypeRule := strings.Join([]string{
		`MM/DD/YYYY|MM/YY|DD/MM/YYYY|N/A|next/router|TLS/SSL|`,
		`application/x-www-form-urlencoded|multipart/form-data|multipart/mixed|multipart/alternative|`,
		`text/partytown|text/x-component|text/css|text/plain|text/html|text/xml|text/csv|text/markdown|text/babel|text/tsx|text/jsx|text/x-yaml|text/yaml|`,
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

	matches := re.FindAllStringSubmatch(string(Body), -1)

	var cleanedMatches []string
	seenLines := make(map[string]bool)

	for _, match := range matches {
		// The new regex captures the URL/path in match[1]
		if len(match) > 1 {
			cleanedMatch := match[1]

			// Skip empty matches
			if cleanedMatch == "" {
				continue
			}

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
