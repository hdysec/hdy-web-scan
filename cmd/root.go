/*
Johann Van Niekerk hdysec@gmail.com
*/

package cmd

import (
	"bufio"
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

var greenPlus = fmt.Sprintf("[%s]", color.HiGreenString("++"))
var redMinus = fmt.Sprintf("[%s]", color.HiRedString("--"))

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "hdyWebScan",
	Short: "A collection of auditing tools automated and vetted",
	Long: `This tool is useful for start or end of engagement scanning that can be executed to gather and understanding
 of existing vulnerabilities as well as ensuring a robust workflow. After using this tool it is HIGHLY recommended to 
ensure you are running similar tools manually and using varied plugins & modules that each tool provides. 

This tool should not be trusted as an all-in-one step as there are missing flags, steps, and modules to speed up this 
scanning process.

Examples:
	hdyWebScan -d "https://example.com" -H "Cookie: connect.sid=s%3A-masdfasdfasdfasdfasdfw" -k
	hdyWebScan -d "http://example.com/merchant" -H "Cookie: connect.sid=s%3A-masdfasdfasdfasdfasdfw" -k -n -b -w
`,

	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		printBanner()

		// Setup and grab domains provided whether as a singular or a list from a file
		domainName, _ := cmd.Flags().GetString("domain")
		domainNameList, _ := cmd.Flags().GetString("domainList")
		domains := loadDomains(domainName, domainNameList)

		// true/false setup for if domains contains 1 URL or multiple
		outputToStdout := len(domains) == 1

		// Check if the domain flag was provided
		userInput, _ := cmd.Flags().GetString("domain")
		if userInput == "" {
			fmt.Println("The 'domain' flag is required.")
			cmd.Help() // Display help menu
			os.Exit(1) // Exit with an error status code
		}

		// Check all Installation and Dependencies
		if !dependencyChecker() {
			fmt.Println("Dependencies not met due to one/all of the following:")
			fmt.Println("		- Ensure Docker and Git are installed")
			fmt.Println("		- Ensure Docker and Git are in $PATH")
			fmt.Println("		- Ensure internet connectivity is working and no issues with DNS or host files")
			return
		}

		// Concurrency to run multiple scans simultaneously
		var wg sync.WaitGroup
		for _, domain := range domains {
			wg.Add(1)
			go func(d string) {
				defer wg.Done()
				//processScan(d, outputFilename)
				processScan(cmd, d, outputToStdout)
			}(domain)
		}
		wg.Wait()

		// end
		fmt.Printf("%s Finished", greenPlus)
	},
}

func printBanner() {
	banner := []string{
		"#-+-+-+-+-+-+-+-+-+-#",
		"#     hdyWebScan    #",
		"#-+-+-+-+-+-+-+-+-+-#",
	}

	for _, line := range banner {
		fmt.Println(line)
	}
}

func dependencyChecker() bool {
	//fmt.Println("Debug: Executing dependencyChecker()")

	// check system OS type before issuing ping command due to different (ping) flag requirements.
	var outboundCheck *exec.Cmd
	if runtime.GOOS == "windows" {
		// Windows ping command, sending 1 packet
		outboundCheck = exec.Command("ping", "google.com", "-n", "1")
	} else {
		// Linux and macOS ping command, sending 1 packet
		outboundCheck = exec.Command("ping", "google.com", "-c", "1")
	}

	// Check for Internet/DNS connectivity
	_, err := outboundCheck.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// The command executed, but ping failed; exitErr.ExitCode() will be non-zero
			fmt.Printf("%s Outbound Ping to google.com unsuccessful with exit code %d\n", redMinus, exitErr.ExitCode())
		} else {
			// The command did not execute successfully (e.g., command not found)
			fmt.Printf("%s Ping command failed to execute: %s\n", redMinus, err)
		}
		os.Exit(1)
	}
	fmt.Printf("%s Check Internet Connectivity\n", greenPlus)

	// Check for Docker installation via CLI
	dockerCheck := exec.Command("docker", "--version")
	if err := dockerCheck.Run(); err != nil {
		fmt.Printf("%s Docker check failed, it is either not installed, not running with elevated privileges, or the process is currently not running: %s\n", redMinus, err)
		os.Exit(1)
	}
	fmt.Printf("%s Check Docker Setup\n", greenPlus)

	// Check for Git installation via CLI - Required for Git Clone
	gitCheck := exec.Command("git", "--version")
	if err := gitCheck.Run(); err != nil {
		fmt.Printf("%s Git check failed, it is either not installed or there is an issue with your PATH: %s\n", redMinus, err)
		os.Exit(1)
	}
	fmt.Printf("%s Check Git Setup\n", greenPlus)

	// Check for Nuclei Installation
	// set variables for remainder of dependency check
	toolGithub := "https://github.com/projectdiscovery/nuclei"
	toolName := "Nuclei" // name as per what the folder name would be

	nucleiCheck := exec.Command("docker", "images", "-q", "projectdiscovery/nuclei:latest")
	output, err := nucleiCheck.Output()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			//fmt.Println("Issues checking if existing image exists for: " + toolName)
			fmt.Printf("%s Issues checking: %s, Standard Error: %s\n", redMinus, toolName, string(exitErr.Stderr))
		} else {
			fmt.Printf("%s Issues checking: %s, Error with program: %s\n", redMinus, toolName, err)
		}
		os.Exit(1)
	}
	if strings.TrimSpace(string(output)) == "" {
		nucleiClone := exec.Command("docker", "pull ", "projectdiscovery/nuclei:latest")
		fmt.Println(nucleiClone)
		if err := nucleiClone.Run(); err != nil {
			fmt.Printf("%s Problems with executing Git Clone %s\n", redMinus, err)
			os.Exit(1)
		}
	}
	fmt.Printf("%s Check Nuclei Setup\n", greenPlus)

	// Check for Nikto Installation
	// set variables for remainder of dependency check
	toolGithub = "https://github.com/sullo/nikto.git"
	toolName = "Nikto" // name as per what the folder name would be

	niktoCheck := exec.Command("docker", "images", "-q", "sullo/nikto")
	output, err = niktoCheck.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			//fmt.Println("Issues checking if existing image exists for: " + toolName)
			fmt.Printf("%s Issues checking: %s, Standard Error: %s\n", redMinus, toolName, string(exitErr.Stderr))
		} else {
			fmt.Printf("%s Issues checking: %s, Error with program: %s\n", redMinus, toolName, err)
		}
		os.Exit(1)
	}

	if strings.TrimSpace(string(output)) == "" {
		niktoClone := exec.Command("git", "clone", toolGithub)
		if err := niktoClone.Run(); err != nil {
			fmt.Printf("%s Problems with executing Git Clone %s\n", redMinus, err)
			os.Exit(1)
		}

		niktoInstall := exec.Command("docker", "build", "-t", "sullo/nikto", "./"+toolName+"/", "--network", "host")
		fmt.Println(niktoInstall)
		if err := niktoInstall.Run(); err != nil {
			fmt.Printf("%s Problems with executing Docker Build on: %s Error: %s\n ", redMinus, toolName, err)
			os.Exit(1)
		}

		// remove the git clone folder as it is not required any more
		err = os.RemoveAll("./" + toolName + "/")
		if err != nil {
			fmt.Printf("%s Failed to delete & remove the remnants from the git cloned files.\n Do it manually as the folder and it's contents are not needed. \n Error: %s", redMinus, err)
		}
	}
	fmt.Printf("%s Check Nikto Setup\n", greenPlus)

	// Check for Wapiti installation
	// overwrite variables for remainder of dependency check
	toolGithub = "https://github.com/wapiti-scanner/wapiti.git" // overwrite variables for remainder of dependency check
	toolName = "Wapiti"                                         // name as per what the folder name would be

	wapitiCheck := exec.Command("docker", "images", "-q", "wapiti-scanner/wapiti")
	output, err = wapitiCheck.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			//fmt.Println("Issues checking if existing image exists for: " + toolName)
			fmt.Printf("%s Issues checking: %s, Standard Error: %s\n", redMinus, toolName, string(exitErr.Stderr))
		} else {
			fmt.Printf("%s Issues checking: %s, Error with program: %s\n", redMinus, toolName, err)
		}
	}

	if strings.TrimSpace(string(output)) == "" {
		wapitiClone := exec.Command("git", "clone", toolGithub)
		if err := wapitiClone.Run(); err != nil {
			fmt.Printf("%s Problems with executing Git Clone %s\n", redMinus, err)
			os.Exit(1)
		}

		wapitiInstall := exec.Command("docker", "build", "-t", "wapiti-scanner/wapiti", "./"+toolName+"/", "--network", "host")
		fmt.Println(wapitiInstall)
		if err := wapitiInstall.Run(); err != nil {
			fmt.Printf("%s Problems with executing Docker Build on: %s Error: %s\n ", redMinus, toolName, err)
			os.Exit(1)
		}

		// remove the git clone folder as it is not required any more
		err = os.RemoveAll("./" + toolName + "/")
		if err != nil {
			fmt.Println("Failed to delete & remove the remnants from the git cloned files.\n Do it manually as the folder and it's contents are not needed. \n Error:", err)
		}
	}
	fmt.Printf("%s Check Wapiti Setup\n", greenPlus)

	// Check for Bbot installation
	// overwrite variables for remainder of dependency check
	toolGithub = "https://github.com/blacklanternsecurity/bbot" // overwrite variables for remainder of dependency check
	toolName = "Bbot"                                           // name as per what the folder name would be

	bbotCheck := exec.Command("docker", "images", "-q", "blacklanternsecurity/bbot")
	output, err = bbotCheck.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			//fmt.Println("Issues checking if existing image exists for: " + toolName)
			fmt.Printf("%s Issues checking: %s, Standard Error: %s\n", redMinus, toolName, string(exitErr.Stderr))
		} else {
			fmt.Printf("%s Issues checking: %s, Error with program: %s\n", redMinus, toolName, err)
		}
		os.Exit(1)
	}
	if strings.TrimSpace(string(output)) == "" {
		bbotClone := exec.Command("docker", "pull ", "blacklanternsecurity/bbot")
		fmt.Println(bbotClone)
		if err := bbotClone.Run(); err != nil {
			fmt.Printf("%s Problems with executing Git Clone %s\n", redMinus, err)
			os.Exit(1)
		}
	}
	fmt.Printf("%s Check Bbot Setup\n", greenPlus)

	// Check for Neo4j installation
	// overwrite variables for remainder of dependency check
	toolGithub = "https://github.com/neo4j/neo4j" // overwrite variables for remainder of dependency check
	toolName = "Neo4j"                            // name as per what the folder name would be

	neo4jCheck := exec.Command("docker", "images", "-q", "neo4j")
	output, err = neo4jCheck.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			//fmt.Println("Issues checking if existing image exists for: " + toolName)
			fmt.Printf("%s Issues checking: %s, Standard Error: %s\n", redMinus, toolName, string(exitErr.Stderr))
		} else {
			fmt.Printf("%s Issues checking: %s, Error with program: %s\n", redMinus, toolName, err)
		}
		os.Exit(1)
	}
	if strings.TrimSpace(string(output)) == "" {
		neo4jClone := exec.Command("docker", "pull ", "neo4j")
		fmt.Println(neo4jClone)
		if err := neo4jClone.Run(); err != nil {
			fmt.Printf("%s Problems with executing Git Clone %s\n", redMinus, err)
			os.Exit(1)
		}
	}
	fmt.Printf("%s Check Neo4j Setup (For Bbot)\n", greenPlus)
	return true
}

func processScan(cmd *cobra.Command, domain string, outputToStdout bool) {
	//fmt.Println("Debug: Enter processScan()")
	headerValue, _ := cmd.Flags().GetString("header")
	sanitisedName := sanitiseURL(domain)
	proxyValue, _ := cmd.Flags().GetString("proxy")
	userAgent := "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0"

	currentTime := time.Now()
	timeString := currentTime.Format("20060102-1504") // YYYYMMDD-hhmm

	// Get the current working directory to use for volume mounting when using Docker and retrieving logs from container
	pwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("Error getting current working directory: %v\n", err)
		return
	}
	outputDir := fmt.Sprintf("%s/output:/output", pwd)

	// Nuclei (-n) - https://github.com/projectdiscovery/nuclei
	runNuclei, _ := cmd.Flags().GetBool("nuclei") // check if nuclei flag is set
	if runNuclei {
		folderName := "nuclei"
		nucleiFile := fmt.Sprintf("./output/%s/Nuclei-CLI.%s.txt", folderName, sanitisedName)
		nucleiBaseArgs := []string{
			"run",
			"--network", "host",
			"-v", outputDir,
			"projectdiscovery/nuclei:latest",
			"-target", domain,
			"-retries", "3",
			"-rl", "50",
			"-c", "10",
			"-tags", "rce,lfi,xss,network,logs,config,ssrf",
			//"-tags", "sqli",
			"-exclude-tags", "cve,intrusive",
			"-timestamp",
			"-markdown-export", "output",
		}

		// Handle Custom Header for Nuclei
		if headerValue != "" {
			nucleiBaseArgs = append(nucleiBaseArgs, "-H", headerValue)
		}
		if proxyValue != "" {
			nucleiBaseArgs = append(nucleiBaseArgs, "-p", headerValue)
		}
		runCommand("docker", nucleiBaseArgs, nucleiFile, outputToStdout, folderName)
		fmt.Printf("%s Nuclei Finished - Check $PWD/output/ for logs.\n", greenPlus)
	}

	// Nikto (-k) - https://github.com/sullo/nikto -k
	runNikto, _ := cmd.Flags().GetBool("nikto") // check if nikto flag is set
	originalURL := domain
	fmt.Println(originalURL)
	if runNikto {
		folderName := "nikto"
		outputFileName := fmt.Sprintf("/output/nikto/nikto-logs-%s.txt", timeString)
		niktoFile := fmt.Sprintf("./output/%s/Nikto-CLI.%s.txt", folderName, sanitisedName)
		exec.Command("docker", "--network", "host", "sullo/nikto", "-update") // update Nikto Database and plugins from CIRT.net
		//niktoBaseArgs := []string{"run", "--rm", "--network", "host", "sullo/nikto", "-host", domain, "-Tuning", "012345789abc", "-Format", "htm", "-o", "."}
		niktoBaseArgs := []string{
			"run",
			"--network", "host",
			"-v", outputDir,
			"sullo/nikto",
			"-host", domain,
			"-Tuning", "012345789abc",
			"-Format", "txt",
			"-o", outputFileName,
		}

		// Handle Custom Header for Nikto
		if headerValue != "" {
			craftedUserAgent := "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0" + string('\r') + string('\n') + headerValue
			envVarName := "NIKTO_USER_AGENT"
			if err := os.Setenv(envVarName, craftedUserAgent); err != nil {
				fmt.Println("Failed to set environment variable:", err)
				return
			}
			useragentValue, exists := os.LookupEnv(envVarName)
			if !exists {
				fmt.Println("Environment variable not found:", envVarName)
				return
			}
			niktoBaseArgs = append(niktoBaseArgs, "-useragent", useragentValue)
		}
		if proxyValue != "" {
			niktoBaseArgs = append(niktoBaseArgs, "-useproxy", proxyValue)
		}

		runCommand("docker", niktoBaseArgs, niktoFile, outputToStdout, folderName)
		fmt.Printf("%s Nikto Finished - Check $PWD/output/ for logs.\n", greenPlus)
	}

	// Bbot (-b) - https://github.com/blacklanternsecurity/bbot
	runBbot, _ := cmd.Flags().GetBool("bbot") // check if nikto flag is set
	if runBbot {
		folderName := "bbot"
		neo4jResults := "http://127.0.0.1:7474/browser/"
		creds := "Creds = neo4j:bbotislife"
		//bbotFile := fmt.Sprintf("./output/Bbot-CLI.%s.txt", sanitisedName)
		bbotFile := fmt.Sprintf("./output/%s/Bbot-CLI.%s.txt", folderName, sanitisedName)
		neo4jOutput := fmt.Sprintf("%s/neo4j/:/data/", pwd)

		// Set API Keys
		var (
			bbotShodanKey         = ""
			bbotSecurityTrailsKey = ""
			bbotCensysIdKey       = ""
			bbotCensysSecret      = ""
			bbotFullHuntKey       = ""
		)

		// Set Bbot yaml file with config settings with API keys and proxy (if any)
		yamlConfig := fmt.Sprintf(
			`http_proxy: %s
modules:
  shodan_dns:
    api_key: %s
  securitytrails:
    api_key: %s
  censys:
    api_id: %s
    api_secret: %s
  fullhunt:
    api_key: %s
`, proxyValue, bbotShodanKey, bbotSecurityTrailsKey, bbotCensysIdKey, bbotCensysSecret, bbotFullHuntKey)

		// Create temp dir that will hold yaml file on HOST
		tmpDir, err := os.MkdirTemp("", "bbot-config")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(tmpDir) // clean up after this function completed

		// Write yaml file to temp directory - This will be mounted and used with BBOT inside docker container
		tmpFilePath := filepath.Join(tmpDir, "bbot.yml")
		if err := os.WriteFile(tmpFilePath, []byte(yamlConfig), 0644); err != nil {
			panic(err)
		}

		exec.Command("docker", "run", "-d", "-p", "7687:7687", "-p", "7474:7474", "-v", neo4jOutput, "-e", "NEO4J_AUTH=neo4j/bbotislife", "neo4j")
		bbotAllowFlags := "safe,passive,subdomain-enum,active,web-thorough,cloud-enum,affiliates,email-enum,iis-shortnames,report,social-enum,web-screenshots"
		bbotExcludeFlags := "aggressive, slow"
		bbotBaseArgs := []string{
			"run",
			"--network", "host",
			"-v", fmt.Sprintf("%s:/root/.config/bbot/bbot.yml", tmpFilePath),
			"-v", outputDir,
			"blacklanternsecurity/bbot",
			"-t", domain,
			//"--strict-scope",
			"-f", bbotAllowFlags,
			"-ef", bbotExcludeFlags,
			"-om", "neo4j",
			"-n", "bbotLogs." + sanitisedName,
			"-o", "/output/" + folderName,
		}

		// Handle Custom Header for Bbot
		if headerValue != "" {
			headerParts := strings.SplitN(headerValue, ": ", 2)
			headerKey := strings.TrimSpace(headerParts[0])
			headerV := strings.TrimSpace(headerParts[1])
			bbotBaseArgs = append(bbotBaseArgs, "--config http_headers={\""+headerKey+"\":\""+headerV+"\"}")
		}
		runCommand("docker", bbotBaseArgs, bbotFile, outputToStdout, folderName)
		fmt.Printf("%s Bbot Finished - Check $PWD/output/ for logs.\n", greenPlus)

		fmt.Printf("%s Review Neo4j Results: %s\n", greenPlus, neo4jResults)
		fmt.Printf("%s Neo4j Login: %s\n", greenPlus, creds)
	}

	// Wapiti-Scanner (-w) - https://github.com/wapiti-scanner/wapiti -w
	runWapiti, _ := cmd.Flags().GetBool("wapiti") // check if wapiti flag is set
	if runWapiti {
		folderName := "wapiti"
		outputFileName := fmt.Sprintf("/output/wapiti/wapiti-logs-%s.txt", timeString)
		wapitiFile := fmt.Sprintf("./output/%s/Wapiti-CLI.%s.txt", folderName, sanitisedName)
		exec.Command("docker", "--network", "host", "wapiti-scanner/wapiti", "--update") // update wapiti database and plugins
		wapitiAllowModules := "backup,cms,cookieflags,crlf,csp,csrf,exec,file,htaccess,htp,http_headers,https_redirect,log4shell,methods,permanentxss,redirect,shellshock,spring4shell,sql,ssrf,takeover,timesql,upload,wapp,wp_enum,xss,xxe"
		wapitiBaseArgs := []string{
			"run",
			"--network", "host",
			"-v", outputDir,
			"wapiti-scanner/wapiti",
			"--url", domain,
			"--scope", "url",
			"--user-agent", userAgent,
			"--module", wapitiAllowModules,
			"--color",
			"--no-bugreport",
			"-f", "csv",
			"-o", outputFileName,
		}

		// Handle Custom Header for Wapiti-Scanner
		if headerValue != "" {
			wapitiBaseArgs = append(wapitiBaseArgs, "-H", headerValue)
		}
		if proxyValue != "" {
			wapitiBaseArgs = append(wapitiBaseArgs, "-p", proxyValue)
		}
		runCommand("docker", wapitiBaseArgs, wapitiFile, outputToStdout, folderName)
		fmt.Printf("%s Wapiti-Scanner Finished - Check $PWD/output/ for logs.\n", greenPlus)
	}
}

func loadDomains(domainName, domainNameList string) []string {
	// Ensuring there is a valid domain name entry in CLI or in text file
	//fmt.Println("Debug: Executing loadDomains()")

	if domainName != "" {
		return []string{domainName}
	}
	if domainNameList != "" {
		return readLinesFromFile(domainNameList)
	}
	return []string{}
}

func readLinesFromFile(filePath string) []string {
	//fmt.Println("Debug: Executing readLinesFromFile()")

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Error opening file %s: %s\n", filePath, err)
		return nil
	}

	// Ensure file is closed once the readLinesFromFile() function has completed
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file %s: %s\n", filePath, err)
	}

	return lines
}

func runCommand(command string, args []string, outputFile string, outputToStdout bool, folderName string) {
	// Display command
	fmt.Printf("%s Running command: %s %s\n", greenPlus, command, strings.Join(args, " "))

	if err := os.MkdirAll("./output/"+folderName, os.ModePerm); err != nil {
		fmt.Printf("Error creating directory: %s\n", err)
	}

	// Create & open the output file
	file, err := os.OpenFile(outputFile, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("%s Error opening file: %s", redMinus, err)
		return
	}

	// Ensure file is closed once the runCommand() function has completed
	defer file.Close()

	// Set up the command
	cmd := exec.Command(command, args...)

	// Create a multi-writer to write to both stdout and the file if URL provided is > 1
	if outputToStdout {
		multiWriter := io.MultiWriter(os.Stdout, file)
		cmd.Stdout = multiWriter
		cmd.Stderr = multiWriter
	} else {
		// if URL provided is > 1 Direct output only to the file
		cmd.Stdout = file
		cmd.Stderr = file
		fmt.Printf("\n\n\n%s Scanning provided domains, please wait \n\n\n", redMinus)
	}

	// Run the command
	err = cmd.Run()
}

func sanitiseURL(url string) string {
	// Remove http:// and https:// protocols from the URL and any special characters in order to name the output files other windows throws errors with special chars.
	sanitiseName := strings.Replace(url, "http://", "", 1)
	sanitiseName = strings.Replace(sanitiseName, "https://", "", 1)
	reg := regexp.MustCompile(`[:<>"/\\|?*]|\.$`)
	sanitiseName = reg.ReplaceAllString(sanitiseName, "-")
	return sanitiseName
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringP("domain", "d", "", "Provide the domain including the protocol (http/s://).")
	rootCmd.PersistentFlags().StringP("domainList", "D", "", "Provide the list of domain names including the protocol (http/s://).")
	rootCmd.PersistentFlags().StringP("header", "H", "", "Provide optional header to include in scanning when doing authenticated scanning.")
	rootCmd.PersistentFlags().StringP("proxy", "P", "", "Provide optional proxy for Burp or Zap interception (http://127.0.0.1:8081)")
	rootCmd.Flags().BoolP("nuclei", "n", false, "Run Nuclei scan")
	rootCmd.Flags().BoolP("nikto", "k", false, "Run Nikto scan")
	rootCmd.Flags().BoolP("bbot", "b", false, "Run Bbot scan")
	rootCmd.Flags().BoolP("wapiti", "w", false, "Run Wapiti scan")
}
