# Dons JS Scanner

Dons JS Scanner is an advanced Python tool designed by [Ali Essam](https://www.linkedin.com/in/dragonked2/) to scan websites and uncover potential sensitive information within JavaScript files. Leveraging asynchronous programming for efficient web crawling and in-depth analysis, this tool is tailored for bug bounty hunters and security professionals seeking to identify and mitigate vulnerabilities effectively.

## 🛠️ Features

- **Asynchronous Scanning:** Utilizes `asyncio` and `aiohttp` for speedy web crawling and JavaScript file analysis.
- **Sensitive Information Detection:** Identifies potential sensitive information using pre-defined regex patterns.
- **Real-Time Notifications:** Sends detailed findings to your Discord channel via webhook for instant alerts.
- **Multiple Output Formats:** Save results in `txt`, `json`, or `csv` formats, catering to diverse reporting needs.
- **User-Friendly Interface:** Interactive prompts guide you through scanning configurations with clear validations.
- **Robust Error Handling:** Comprehensive exception management ensures smooth and reliable operations.
- **Efficient Resource Management:** Controls concurrency to optimize performance without overwhelming target servers.
- **Detailed Logging:** Maintains comprehensive logs for auditing and troubleshooting purposes.

## 🚀 Getting Started

### 📝 Prerequisites

- **Python 3.7 or higher**
- **Dependencies:** `aiohttp`, `beautifulsoup4`, `rich`, `jsbeautifier`

### 🔧 Installation

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/dragonked2/Dons.git
    cd Dons
    ```

2. **Create a Virtual Environment (Optional but Recommended):**
    ```bash
    python -m venv env
    # Activate the virtual environment
    # On Windows:
    env\Scripts\activate
    # On macOS/Linux:
    source env/bin/activate
    ```

3. **Install Dependencies:**
    ```bash
    pip install aiohttp beautifulsoup4 rich jsbeautifier
    ```

## 🧰 Usage

### 🔍 Scan a Single Website

1. **Run the Scanner:**
    ```bash
    python main.py
    ```

2. **Follow the Prompts:**
    - **Discord Webhook URL:** Enter your Discord webhook URL to receive real-time notifications. Leave blank to skip.
    - **Scan Type:** Choose `single` to scan individual websites.
    - **Website URL:** Enter the website URL you wish to scan. Type `done` when finished.
    - **Recursive Depth:** Specify how deep the crawler should traverse links. Default is `4`.
    - **Concurrency:** Set the number of concurrent connections. Default is `50`.
    - **Output Format:** Choose between `txt`, `json`, or `csv`.

### 📄 Scan Multiple Websites from a File

1. **Prepare a File:**
    - Create a text file (e.g., `websites.txt`) with one website URL per line.
    
2. **Run the Scanner:**
    ```bash
    python main.py
    ```

3. **Follow the Prompts:**
    - **Discord Webhook URL:** Enter your Discord webhook URL or leave blank to skip.
    - **Scan Type:** Choose `file` to scan multiple websites.
    - **File Path:** Provide the path to your `websites.txt` file.
    - **Recursive Depth:** Specify the recursive depth. Default is `4`.
    - **Concurrency:** Set the number of concurrent connections. Default is `50`.
    - **Output Format:** Choose between `txt`, `json`, or `csv`.

### 🔄 Customize Scan Depth and Concurrency

- **Recursive Depth:** Determines how deep the crawler explores linked pages. Higher values increase thoroughness but also scanning time.
- **Concurrency:** Controls the number of simultaneous connections. Adjust based on your system's capabilities and target servers' responsiveness.

## 📂 Results

- **Output Files:** Results are saved in the chosen format (`txt`, `json`, or `csv`) on your Desktop.
- **Console Output:** Findings are displayed in structured tables within the console.
- **Discord Notifications:** If configured, detailed notifications are sent to your specified Discord channel for each finding.
- **Logs:** Detailed logs are maintained in `website_scanner.log` for auditing and troubleshooting.

### 📝 Example

```plaintext
Matches found at https://example.com, JavaScript file: https://example.com/js/main.js:

Key: Google API Key
  Snippet: AIzaSyD...

Key: AWS Secret Key
  Snippet: aws_secret_access_key='ABCDEF1234567890abcdef1234567890abcdef'
```

### 📈 Sample Discord Notification

![Discord Notification](https://github.com/dragonked2/Dons/assets/66541902/ad02ae1e-8f30-4ef3-ad35-95735f1cfeb7)

## 🤝 Contributions

Contributions are always welcome! If you have suggestions, bug fixes, or new features, feel free to open an issue or submit a pull request.

## 🌐 Connect with Me

[![LinkedIn](https://img.shields.io/badge/LinkedIn-DragonKed2-blue?logo=linkedin)](https://www.linkedin.com/in/dragonked2/)

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <p>Feel free to star ⭐️ the repository if you find it helpful! 🚀</p>
</div>
```

---

### **Key Updates and Enhancements**

1. **Fixed Logging Handler Error:**
   - **Issue Resolved:** The error `AttributeError: module 'logging' has no attribute 'handlers'. Did you mean: '_handlers'?` was caused by incorrect referencing of the `RotatingFileHandler`.
   - **Solution Implemented:** Correctly imported and utilized `RotatingFileHandler` from `logging.handlers` to ensure proper log file management.

2. **Removed High Entropy String Detection:**
   - **Enhancement:** All functionalities related to detecting high entropy strings have been removed. The scanner now strictly relies on predefined regex patterns to identify sensitive information.

3. **Enhanced Discord Notifications:**
   - **Full Data Transmission:** Discord notifications now include the full matched snippet within a code block for better readability and context.
   - **Detailed Information:** Notifications provide comprehensive details including the key, full snippet, and source URL.

4. **Improved User Interaction:**
   - **Interactive Prompts:** Enhanced prompts guide users through inputting multiple website URLs interactively when selecting the single scan option.
   - **Input Validations:** Ensured that all user inputs (e.g., URLs, depth, concurrency) are validated for correctness and completeness.
   - **Graceful Exits:** If no websites are entered, the script exits gracefully with an informative message.

5. **Robust Error Handling and Logging:**
   - **Comprehensive Exception Management:** The script includes extensive try-except blocks to catch and log unexpected errors without crashing.
   - **Retry Mechanism:** Implemented a retry mechanism in the `fetch` method to handle transient network issues effectively.
   - **Detailed Logs:** Enhanced logging with rotating file handlers to prevent log files from becoming excessively large, ensuring maintainability.

6. **Optimized Concurrency Control:**
   - **Efficient Resource Utilization:** Utilized `asyncio.Semaphore` to manage the number of concurrent connections, preventing the overwhelming of target servers and optimizing scanning performance.

7. **User-Friendly Output:**
   - **Rich Library Integration:** Leveraged the `rich` library to display visually appealing progress bars, tables, and panels, enhancing the overall user experience.
   - **Multiple Output Formats:** Allowed users to choose between `txt`, `json`, or `csv` formats for saving scan results, catering to diverse analysis and reporting needs.

8. **Code Cleanliness and Readability:**
   - **Organized Structure:** The code is organized into clear sections with concise comments, ensuring better readability and maintainability.
   - **Consistent Naming Conventions:** Maintained consistent naming conventions and code formatting standards throughout the script.

---

### **Final Recommendations**

- **Ensure Correct Dependencies:** Verify that all required Python packages (`aiohttp`, `beautifulsoup4`, `rich`, `jsbeautifier`) are installed in your environment to avoid runtime errors.
  
- **Secure Your Discord Webhook:** Keep your Discord webhook URL confidential to prevent unauthorized access and potential misuse.

- **Regularly Update Regex Patterns:** To maintain the effectiveness of the scanner, periodically update the regex patterns within the script to adapt to new types of sensitive information and evolving security threats.

- **Ethical Usage:** Always ensure you have explicit permission to scan target websites to comply with legal and ethical standards, avoiding unauthorized scanning activities.

- **Performance Tuning:** Adjust the recursive depth and concurrency settings based on your system's capabilities and the target servers' responsiveness to optimize scanning performance.
