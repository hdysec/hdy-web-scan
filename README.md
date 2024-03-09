# WebApp Vulnerability Scan Wrapper

hdyWebScan is part of a set of personal tools developed to cover robust simple checks and automation. This is a personal project for my personal workflow and may/may not receive updates and may/may not work. Who knows. :shrug:

## Description

hdyWebScan is a wrapper tool that calls on a set of favourite Web Application auditing tools to perform preliminary  scans and testing against known easy and well known vulnerabilities. I am not the author of the invoked tools and all credit goes to their hard work. 

**Note:** Further improvements planned to include custom scripts and checks to provide wider coverage. Tool is relatively simple to scale and as such will continue to add further functionality and tools as I find and experiment with them.

**Credits:**

 - https://github.com/sullo/nikto
 - https://github.com/projectdiscovery/nuclei
 - https://github.com/wapiti-scanner/wapiti
 - https://github.com/blacklanternsecurity/bbot

The primary use for this tool is to automate and complete an initial and rudimentary scan on web applications and domains. It uses several tools to perform this in order to cover edge cases and then outputs the content from these tools to their respective files for your **manual review**.

It is a simple automation tool to ensure I cover the basics and nothing more.

![](https://i.imgur.com/vrle5QF.png)

**Features**

- **Configurable**: You can easily edit the code to include additional tools to be executed or adapt the flags for your own custom templates and configurations. Useful as depending on client environment, you may need to rate limit or adapt.
- **Initial Scan Coverage**: Comes pre-configured with flags and settings to cover the initial scans without integrating the more time-consuming scans. This is left for you to perform at the end of your engagement or whenever.
- **OS-agnostic**:  Tool is **OS-agnostic** as the application is built for portability in mind and can be compiled natively for both Windows and Linux platforms. 
- **Docker Execution**: The application executes and uses only Docker containers, (or sets up the docker images for you) for each step thereby removing the need for further dependencies and installation steps in order to function.
- **Proxy Requests**: **Proxying** to Burp, Zap, or whatever, is simple to easily assist with reviewing configurations and confirming the validity of the findings.
- **Custom HTTP Headers**: Easily allows for **custom HTTP headers** to provide utility when dealing with unauthenticated and authenticated scanning as well as dealing with edge-cases that require certain headers to successfully interact with the application as intended.
- **Neo4j Prettiness**: Bbot output is directly copied into a docker image with Neo4j - this will be easily accessible to graph the findings.
- **Granular Control on Execution**: Provide flags for all tools or only 1 or 2. The tool will proceed with the desired configuration.
- Whatever features are part of the wrapped programs.
- Also, you can provide it a single URL or a list of URLs via feeding a .txt file.

## Requirements

Dependencies include the following to be installed prior to using this tool:

 - Docker
 - Git

## Installation

As always, review code before using public tools. Program is written in golang; you will need Go installed in order to compile. Code is very simple, and you can easily adjust to add your own comments, headers, and recommendations you want to keep track of.

```
$ git clone https://github.com/hdysec/hdy-web-scan.git
$ cd hdy-web-scan
$ go build .
```

## Usage

```
Examples:
        hdyWebScan -d "https://example.com" -H "Cookie: connect.sid=s%3A-masdfasdfasdfasdfasdfw" -k
        hdyWebScan -d "http://example.com/merchant" -H "Cookie: connect.sid=s%3A-masdfasdfasdfasdfasdfw" -k -n -b -w

Usage:
  hdyWebScan [flags]

Flags:
  -b, --bbot                Run Bbot scan
  -d, --domain string       Provide the domain including the protocol (http/s://).
  -D, --domainList string   Provide the list of domain names including the protocol (http/s://).
  -H, --header string       Provide optional header to include in scanning when doing authenticated scanning.
  -h, --help                help for hdyWebScan
  -k, --nikto               Run Nikto scan
  -n, --nuclei              Run Nuclei scan
  -P, --proxy string        Provide optional proxy for Burp or Zap interception (http://127.0.0.1:8081)
  -w, --wapiti              Run Wapiti scan
```

**Disclaimer**:

- Sharing because sharing is caring.
- Always review your local laws regarding use of tools that facilitate penetration testing and always seek permission before performing any testing on a client.


