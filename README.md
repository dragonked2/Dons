![380024582_904511401099198_7120165947283670814_n](https://github.com/dragonked2/Dons/assets/66541902/ad02ae1e-8f30-4ef3-ad35-95735f1cfeb7)

# WebScanner - Website JavaScript Scanner

## Overview

WebScanner is a Python tool designed to scan websites and identify potentially sensitive information in JavaScript files. It utilizes regular expressions to search for patterns associated with API keys, access tokens, and other sensitive data. The tool is capable of scanning multiple websites from a file or a single website and provides detailed information about the identified matches.

## Features

- **Versatile Scanning:** WebScanner employs a wide range of regular expressions to identify sensitive information, including API keys, access tokens, and various credentials.
- **Multi-Website Scanning:** Scan multiple websites listed in a file or provide a single website URL for analysis.
- **Recursive Depth:** Specify the depth of recursion for scanning linked pages within a website.
- **Concurrency:** Utilizes multithreading to enhance scanning speed by concurrently analyzing JavaScript files.

## Installation

To use WebScanner, ensure you have Python installed. Install the required dependencies using the following command:

```bash
pip install requests beautifulsoup4 tqdm
```

## Usage

1. Run the script by executing the following command in your terminal:

```bash
python webscanner.py
```

2. Choose whether to scan multiple websites from a file or a single website.
3. Provide the necessary inputs, such as the file path or website URL and the desired recursive depth.
4. Let WebScanner perform the scanning process, and the results will be displayed on the console.

## Examples

### Scanning Multiple Websites from a File

```bash
Scan multiple websites from a file or a single website? (Enter 'file' or 'single'): file
Enter the path to the file containing website URLs: websites.txt
Enter the recursive depth for scanning (default is 4): 3
```

### Scanning a Single Website

```bash
Scan multiple websites from a file or a single website? (Enter 'file' or 'single'): single
Enter the website URL: https://example.com
Enter the recursive depth for scanning (default is 4): 2
```

## Disclaimer

WebScanner is intended for educational and security research purposes only. Be sure to have the necessary permissions before scanning any website. The tool is not responsible for any misuse or illegal activities.

## Contributions

Contributions are welcome! Feel free to submit issues or pull requests to enhance the functionality of WebScanner.

## License
## Ali Essam
This tool is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
