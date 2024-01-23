![380024582_904511401099198_7120165947283670814_n](https://github.com/dragonked2/Dons/assets/66541902/ad02ae1e-8f30-4ef3-ad35-95735f1cfeb7)


```markdown

# Dons Js Scanner: Detect Secrets in JavaScript Files

Dons Js Scanner is a powerful Python tool crafted by [Ali Essam](https://www.linkedin.com/in/dragonked2/) for scanning websites and uncovering potential sensitive information within JavaScript files. Harnessing the strength of asynchronous programming, this tool ensures efficient web crawling and in-depth analysis.

## Features 🚀

- **Asynchronous Scanning:** Utilizes asyncio and aiohttp for speedy web crawling and JavaScript file analysis.
- **Sensitive Information Detection:** Identifies potential sensitive information using pre-defined regex patterns.
- **Result Clustering:** Presents cleaner output by clustering similar results.

## Getting Started 🛠️

### Prerequisites 📋

- Python 3.7 or higher
- Dependencies: aiohttp, BeautifulSoup, termcolor, tqdm, coloredlogs

### Installation 🚀

1. **Clone the repository:**

   ```bash
   git clone https://github.com/dragonked2/Dons.git
   cd Dons
   ```

2. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

## Usage 🌐

### Scan Single Website 🕸️

```bash
python main.py
```

Follow the prompts to enter a single website URL for scanning.

### Scan Multiple Websites from a File 📄

```bash
python main.py
```

Choose the option to scan multiple websites from a file and provide the file path.

### Customizing Scan Depth ⚙️

You can customize the recursive depth for scanning when prompted. The default depth is set to 4.

## Results 📊

Detected matches will be saved to a file on your desktop and displayed in the console.

## Example 🎉

```bash
Matches found at https://example.com, JavaScript file: https://example.com/js/main.js:

  Key: Google API Key
    Snippet: AIza...

  Key: Google Cloud Pub/Sub Emulator Host
    Snippet: google.pubsub.emulator.host = 'example.appspot.com'
```

## Contributions 🤝

Contributions are always welcome! Feel free to open issues or pull requests.

## Connect with Me 🌐
## Ali Essam 📄
- [LinkedIn](https://www.linkedin.com/in/dragonked2/)

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

<div align="center">
  <p>Feel free to star ⭐️ the repository if you find it helpful! 🚀</p>
</div>
```
