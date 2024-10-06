# VulnKnox
VulnKnox is a powerful command-line tool written in Go that interfaces with the [KNOXSS API](https://knoxss.me/?page_id=2729). It automates the process of testing URLs for Cross-Site Scripting (XSS) vulnerabilities using the advanced capabilities of the KNOXSS engine.

## Features
- Supports pipe input for passing file lists and echoing URLs for testing
- Configurable retries and timeouts
- Supports GET, POST, and BOTH HTTP methods
- Advanced Filter Bypass (AFB) feature
- Flash Mode for quick XSS polyglot testing
- CheckPoC feature to verify the proof of concept
- Concurrent processing with configurable parallelism
- Custom headers support for authenticated requests
- Proxy support
- Discord webhook integration for notifications
- Detailed output with color-coded results

### Installation

```bash
go install github.com/iqzer0/vulnknox@latest
```
## Configuration
Before using the tool, you need to set up your configuration:

API Key

Obtain your KNOXSS API key from [knoxss.me](https://knoxss.me).

On the first run, a default configuration file will be created at:

Linux/macOS: `~/.config/vulnknox/config.json`<br />
Windows: `%APPDATA%\VulnKnox\config.json`<br />
Edit the config.json file and replace `YOUR_API_KEY_HERE` with your actual API key.

Discord Webhook (Optional)

If you want to receive notifications on Discord, add your webhook URL to the config.json file or use the -dw flag.

#### Usage

```
Usage of vulnknox:

  -u          Input URL to send to KNOXSS API
  -i          Input file containing URLs to send to KNOXSS API
  -X GET      HTTP method to use: GET, POST, or BOTH
  -pd         POST data in format 'param1=value&param2=value'
  -headers    Custom headers in format 'Header1:value1,Header2:value2'
  -afb        Use Advanced Filter Bypass
  -checkpoc   Enable CheckPoC feature
  -flash      Enable Flash Mode
  -o          The file to save the results to
  -ow         Overwrite output file if it exists
  -oa         Output all results to file, not just successful ones
  -s          Only show successful XSS payloads in output
  -p 3        Number of parallel processes (1-5)
  -t 600      Timeout for API requests in seconds
  -dw         Discord Webhook URL (overrides config file)
  -r 3        Number of retries for failed requests
  -ri 30      Interval between retries in seconds
  -sb 0       Skip domains after this many 403 responses
  -proxy      Proxy URL (e.g., http://127.0.0.1:8080)
  -v          Verbose output
  -version    Show version number
  -no-banner  Suppress the banner
  -api-key    KNOXSS API Key (overrides config file)
```
#### Basic Examples
Test a single URL using GET method:
```bash
vulnknox -u "https://example.com/page?param=value"
```
Test a URL with POST data:
```bash
vulnknox -u "https://example.com/submit" -X POST -pd "param1=value1&param2=value2"
```
Enable Advanced Filter Bypass and Flash Mode:
```bash
vulnknox -u "https://example.com/page?param=value" -afb -flash
```
Use custom headers (e.g., for authentication):
```bash
vulnknox -u "https://example.com/secure" -headers "Cookie:sessionid=abc123"
```
Process URLs from a file with 5 concurrent processes:
```bash
vulnknox -i urls.txt -p 5
```
Send notifications to Discord on successful XSS findings:
```bash
vulnknox -u "https://example.com/page?param=value" -dw "https://discord.com/api/webhooks/your/webhook/url"
```
#### Advanced Usage
Test both GET and POST methods with CheckPoC enabled:
```bash
vulnknox -u "https://example.com/page" -X BOTH -checkpoc
```
Use a proxy and increase the number of retries:
```bash
vulnknox -u "https://example.com/page?param=value" -proxy "http://127.0.0.1:8080" -r 5
```
Suppress the banner and only show successful XSS payloads:
```bash
vulnknox -u "https://example.com/page?param=value" -no-banner -s
```
#### Output Explanation
```
[ XSS! ]: Indicates a successful XSS payload was found.
[ SAFE ]: No XSS vulnerability was found in the target.
[ ERR! ]: An error occurred during the request.
```
The tool also provides a summary at the end of execution, including the number of requests made, successful XSS findings, safe responses, errors, and any skipped domains.

### Contributing
Contributions are welcome! If you have suggestions for improvements or encounter any issues, please open an issue or submit a pull request.

### License
This project is licensed under the MIT License.

### Credits
[@KN0X55](https://x.com/kn0x55)<br />
[@BruteLogic](https://x.com/BRuteLogic)<br />
[@xnl_h4ck3r](https://x.com/xnl_h4ck3r)



