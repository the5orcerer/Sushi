# Sushi

Sushi is a specialized tool for passive subdomain enumeration 🍣. It is designed to identify subdomains for a given domain by querying a variety of passive data sources. Utilizing multiple public APIs and scraping techniques, Sushi simplifies and automates the process of collecting subdomain information. The tool can handle both individual domains and bulk domain lists, saving the results in a structured and user-friendly output file.

## Features
- Aggregates subdomain data from numerous passive sources, including crt.sh, certspotter, web.archive.org, and others.
- Supports enumeration for single domains as well as batch processing for multiple domains.
- Employs concurrent processing to enhance the speed of subdomain discovery.
- Automatically deduplicates and sorts results for clarity.
- Saves the final output to a user-specified file.

---

## Installation

To get started with Sushi, you can either install it using a single command or build it from source.

### One-Command Installation
If Go (version 1.19 or newer) is installed on your system, you can install Sushi quickly with:
```bash
go install -v github.com/the5orcerer/sushi@latest
```
This command downloads, compiles, and places the Sushi binary in your Go `bin` directory, making it instantly available for use.

### Build from Source
For a manual installation, follow these steps:

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/sushi.git
   cd sushi
   ```

2. **Install Dependencies**
   Use Go modules to initialize and download dependencies:
   ```bash
   go mod tidy
   ```

3. **Build the Tool**
   Compile the Sushi binary:
   ```bash
   go build -o sushi
   ```

Once built, you can run Sushi directly from the command line.

---

## Usage & Example

### Basic Usage
Sushi requires either a single domain or a file containing multiple domains to begin enumeration. Command-line arguments include:

- `-d`: Specify a single domain for subdomain enumeration.
- `-f`: Provide a file containing a list of domains.
- `-o`: Define an output file for the results (default: `subdomains.txt`).

### Examples

#### Single Domain Enumeration
```bash
./sushi -d example.com -o example_subdomains.txt
```
This command enumerates subdomains for `example.com` and saves them to `example_subdomains.txt`.

#### Multiple Domains Enumeration
```bash
./sushi -f domains.txt -o all_subdomains.txt
```
This command processes all domains listed in `domains.txt` and saves the results to `all_subdomains.txt`.

### Output
The results are saved in the specified output file, where each line represents a unique subdomain. The output is sorted and free from duplicates for ease of use.

---

## Supported Passive Sources
Sushi integrates with a variety of APIs and services to collect subdomain data, including:
- [crt.sh](https://crt.sh/)
- [certspotter](https://certspotter.com/)
- [web.archive.org](https://web.archive.org/)
- [AlienVault OTX](https://otx.alienvault.com/)
- [ThreatMiner](https://www.threatminer.org/)
- [BufferOver](https://dns.bufferover.run/)
- [Anubis](https://jldc.me/anubis/)

---

## Notes
- Ensure you have a stable internet connection, as Sushi relies on external APIs for data.
- Be mindful of API rate limits; processing a large number of domains may take additional time.
- Use this tool responsibly and only with explicit permission for the domains you test.

---

Happy Hacking with Sushi! 🍣

