// https://github.com/edoardottt/cariddi/blob/main/pkg/scanner/secrets.go

package scanner

type Secret struct {
	Name           string
	Description    string
	Regex          string
	FalsePositives []string
	Poc            string
}

type SecretMatched struct {
	Secret Secret
	URL    string
	Match  string
}

// GetSecretRegexes returns a slice of all
func GetSecretRegexes() []Secret {

	// Regexes from https://github.com/edoardottt/cariddi/blob/main/pkg/scanner/secrets.go
	var regexes = []Secret{
		{
			"AWS Access Key",
			"AWS Access Key",
			"(A3T[A-Z0-9]|AKIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA|ASCA|APKA)[A-Z0-9]{16}",
			[]string{},
			"?",
		},
		{
			"AWS Secret Key",
			"AWS Secret Key",
			`(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]`,
			[]string{},
			"?",
		},
		{
			"AWS MWS Key",
			"AWS MWS Key",
			`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
			[]string{},
			"?",
		},
		{
			"Facebook Access Token",
			"Facebook Access Token",
			`EAACEdEose0cBA[0-9A-Za-z]+`,
			[]string{},
			"?",
		},
		{
			"Facebook Secret Key",
			"Facebook Secret Key",
			`(?i)(facebook|fb)(.{0,20})?(?-i)['\"][0-9a-f]{32}['\"]`,
			[]string{"facebook.com", "facebook.svg"},
			"?",
		},
		{
			"Cloudinary Basic Auth",
			"Cloudinary Basic Auth",
			`cloudinary://[0-9]{15}:[0-9A-Za-z\-_]+@[0-9A-Za-z\-_]+`,
			[]string{},
			"?",
		},
		{
			"Twitter Secret Key",
			"Twitter Secret Key",
			`(?i)twitter(.{0,20})?[0-9a-z]{35,44}`,
			[]string{"twitter.com"},
			"?",
		},
		{
			"Github Personal Access Token",
			"Github Personal Access Token",
			`ghp_.{36}`,
			[]string{},
			"?",
		},
		{
			"Github Personal Access Token",
			"Github Personal Access Token",
			`github_pat_.{82}`,
			[]string{},
			"?",
		},
		{
			"Github OAuth Access Token",
			"Github OAuth Access Token",
			`gho_.{36}`,
			[]string{},
			"?",
		},
		{
			"Github App Token",
			"Github App Token",
			`(ghu|ghs)_.{36}`,
			[]string{},
			"?",
		},
		{
			"Github Refresh Token",
			"Github Refresh Token",
			`ghr_.{76}`,
			[]string{},
			"?",
		},
		{
			"LinkedIn Secret Key",
			"LinkedIn Secret Key",
			`(?i)linkedin(.{0,20})?[0-9a-z]{16}`,
			[]string{"linkedin.com", "linkedin.svg"},
			"?",
		},
		{
			"Slack",
			"Slack",
			`xox[baprs]-([0-9a-zA-Z]{10,48})?`,
			[]string{},
			"?",
		},
		{
			"Asymmetric Private Key",
			"Asymmetric Private Key",
			`-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----`,
			[]string{},
			"?",
		},
		{
			"Heroku API key",
			"Heroku API key",
			`(?i)heroku(.{0,20})?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
			[]string{},
			"?",
		},
		{
			"MailChimp API key",
			"MailChimp API key",
			`[0-9a-f]{32}-us[0-9]{1,2}`,
			[]string{},
			"?",
		},
		{
			"Mailgun API key",
			"Mailgun API key",
			`key\-[0-9a-zA-Z]{32}`,
			[]string{},
			"?",
		},
		{
			"PayPal Braintree access token",
			"PayPal Braintree access token",
			`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
			[]string{},
			"?",
		},
		{
			"Picatic API key",
			"Picatic API key",
			`sk\_live\_[0-9a-z]{32}`,
			[]string{},
			"?",
		},
		{
			"SendGrid API Key",
			"SendGrid API Key",
			`SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}`,
			[]string{},
			"?",
		},
		{
			"Slack Webhook",
			"Slack Webhook",
			`https\:\/\/hooks\.slack\.com/services/T[0-9A-Za-z\-_]{8}/B[0-9A-Za-z\-_]{8}/[0-9A-Za-z\-_]{24}`,
			[]string{},
			"?",
		},
		{
			"Stripe API key",
			"Stripe API key",
			`(?i)stripe(.{0,20})?[sr]k_live_[0-9a-zA-Z]{24}`,
			[]string{},
			"?",
		},
		{
			"Square OAuth secret",
			"Square OAuth secret",
			`sq0csp\-[0-9A-Za-z\-_]{43}`,
			[]string{},
			"?",
		},
		{
			"Twilio API key",
			"Twilio API key",
			`(?i)twilio(.{0,20})?SK[0-9a-f]{32}`,
			[]string{},
			"?",
		},
		{
			"Dynatrace token",
			"Dynatrace token",
			`dt0[a-zA-Z]{1}[0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}`,
			[]string{},
			"?",
		},
		{
			"Shopify shared secret",
			"Shopify shared secret",
			`shpss\_[a-fA-F0-9]{32}`,
			[]string{},
			"?",
		},
		{
			"Shopify access token",
			"Shopify access token",
			`shpat\_[a-fA-F0-9]{32}`,
			[]string{},
			"?",
		},
		{
			"Shopify custom app access token",
			"Shopify custom app access token",
			`shpca\_[a-fA-F0-9]{32}`,
			[]string{},
			"?",
		},
		{
			"Shopify private app access token",
			"Shopify private app access token",
			`shppa\_[a-fA-F0-9]{32}`,
			[]string{},
			"?",
		},
		{
			"Seen in the past tokens",
			"Seen in the past tokens",
			`(?i)['|"](DISCOVERY_IAM_APIKEY|appPassword|slackToken|slack_signing_secret|watson_assistant_api_key|pythonPassword)['|"]`,
			[]string{},
			"?",
		},
		{
			"Secret indicator with _",
			"Secret indicator with _",
			`(?i)['|"][a-zA-Z0-9\-]+[\.|\-|_](access-key|apikey|secret|access_key|secret-key|pwd|passwd|appsecret|app_secret)['|"](\s*?):(\s*?)['|"].*?['|"](\s*?)`,
			[]string{},
			"?",
		},
		{
			"PyPI upload token",
			"PyPI upload token",
			`pypi\-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,1000}`,
			[]string{},
			"?",
		},
		{
			"AWS cognito pool",
			"AWS Cognito pool",
			`(us-east-1|us-east-2|us-west-1|us-west-2|sa-east-1):[0-9A-Za-z]{8}-[0-9A-Za-z]{4}` +
				`-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{12}`,
			[]string{},
			"?",
		},
		{
			"Discord Webhook",
			"Discord Webhook",
			`https\:\/\/discordapp\.com\/api\/webhooks\/[0-9]+/[A-Za-z0-9\-]+`,
			[]string{},
			"?",
		},
		{
			"Google Calendar URI",
			"Google Calendar URI",
			`https\:\/\/(.*)calendar\.google\.com\/calendar\/[0-9a-z\/]+\/embed\?src=[A-Za-z0-9%@&;=\-_\.\/]+`,
			[]string{},
			"?",
		},
		{
			"Google OAuth Access Key",
			"Google OAuth Access Key",
			`ya29\.[0-9A-Za-z\-_]+`,
			[]string{},
			"?",
		},
		{
			"Mapbox Token Disclosure",
			"Mapbox Token Disclosure",
			`(pk|sk)\.eyJ1Ijoi\w+\.[\w-]*`,
			[]string{},
			"?",
		},
		{
			"Microsoft Teams Webhook",
			"Microsoft Teams Webhook",
			`https\:\/\/outlook\.office\.com\/webhook\/[A-Za-z0-9\-@]+\/IncomingWebhook\/[A-Za-z0-9\-]+\/[A-Za-z0-9\-]+`,
			[]string{},
			"?",
		},
		{
			"Generic Keys",
			"Generic Keys",
			`(?i)(?:(?:access_key|access_token|admin_pass|admin_user|algolia_admin_key|x-algolia-api-key|algolia_api_key|alias_pass|alicloud_access_key|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|conn.login|connectionstring|consumer_key|consumer_secret|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_.\-,]{0,25})[:<>=|]{1,2}.{0,5}['"]([0-9a-zA-Z\-_=]{8,64})['"]`,
			[]string{},
			"?",
		},
		{
			"JWT Token",
			"Check For JWT Token",
			`eyJ[0-9A-Za-z-_]+\.[0-9A-Za-z-_]+\.[0-9A-Za-z-_]{43,}`,
			[]string{},
			"?",
		},
		{
			"Secrets From js miner",
			"Check Keys in keyhacks",
			`['"` + "`]?(\\w*)" + // Starts with a quote then a word / white spaces
				`(\s*)` +
				`(secret|passwd|authorization|bearer|aws_access_key_id|aws_secret_access_key|irc_pass|SLACK_BOT_TOKEN|id_dsa|` +
				`secret[_-]?(key|token|secret)|` +
				`api[_-]?(key|token|secret)|` +
				`access[_-]?(key|token|secret)|` +
				`auth[_-]?(key|token|secret)|` +
				`session[_-]?(key|token|secret)|` +
				`consumer[_-]?(key|token|secret)|` +
				`public[_-]?(key|token|secret)|` +
				`client[_-]?(id|token|key)|` +
				`ssh[_-]?key|` +
				`encrypt[_-]?(secret|key)|` +
				`decrypt[_-]?(secret|key)|` +
				`github[_-]?(key|token|secret)|` +
				`slack[_-]?token)` +
				`(\w*)` + // in case there are any characters / white spaces
				`(\s*)` +
				`['"` + "`]?" + // closing quote for variable name
				`(\s*)` + // white spaces
				`[:=]+[:=>]?` + // assignments operation
				`(\s*)` +
				`['"` + "`]" + // opening quote for secret
				`(\s*)` +
				`([\w\-/~!@#$%^&*+]+)` + // Assuming secrets will be alphanumeric with some special characters
				`(\s*)` +
				`['"` + "`]",
			[]string{},
			"?",
		},
	}
	return regexes
}

// RemoveDuplicateSecrets removes duplicates from secrets found.
func RemoveDuplicateSecrets(input []SecretMatched) []SecretMatched {
	keys := make(map[string]bool)
	list := []SecretMatched{}

	for _, entry := range input {
		if _, value := keys[entry.Match]; !value {
			keys[entry.Match] = true
			list = append(list, entry)
		}
	}

	return list
}
