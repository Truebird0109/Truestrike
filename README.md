# Truestrike

Truestrike is a Python-based automation framework for web reconnaissance and vulnerability assessment. It streamlines the process of mapping a target application’s attack surface, performing directory and file enumeration, analyzing static assets, and testing for common injection vulnerabilities.

## Key Features

- **Modular Design**  
  Each major step—reconnaissance, directory enumeration, static analysis, vulnerability scanning, and full-pipeline execution—is encapsulated in its own module, allowing you to run and extend only the components you need.

- **Reconnaissance**  
  - DNS resolution and subdomain discovery  
  - WHOIS lookup and basic banner grabbing  
  - Passive and active reconnaissance options

- **Directory and File Enumeration**  
  - Customizable wordlists for brute-forcing paths  
  - Optional 403 bypass techniques  
  - Configurable depth and thread pool size for large targets

- **Static Asset Analysis**  
  - JavaScript and CSS scraper for extracting inline code and configuration snippets  
  - Identification of hard-coded endpoints, tokens, and API keys  
  - Preliminary mapping of client-side logic and routes

- **Vulnerability Scanning**  
  - XSS and SQL Injection payload delivery with basic response checks  
  - Time-based SQLi tests for blind vulnerabilities  
  - SSRF and SSTI payload templates  
  - Extensible payload library for custom tests

- **Full-Automation Mode**  
  A single entry point (`full_auto.run()`) that orchestrates all available modules in sequence, allowing rapid end-to-end testing.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Truebird0109/Truestrike.git
   cd Truestrike


2. Create a virtual environment and install dependencies:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## Usage

1. Launch the interactive menu:

   ```bash
   python3 main.py
   ```

2. Select the module you wish to run:

   * Reconnaissance
   * Directory Enumeration
   * Static Analysis
   * Vulnerability Scan
   * Full Automation


