![380024582_904511401099198_7120165947283670814_n](https://github.com/dragonked2/Dons/assets/66541902/ad02ae1e-8f30-4ef3-ad35-95735f1cfeb7)


<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
Dons Js Scanner
</head>

<body>

  <h1>Dons Js Scanner</h1>

  <p>Dons Js Scanner is a Python tool designed by <a href="https://www.linkedin.com/in/dragonked2/">Ali Essam</a> to scan websites and uncover potential sensitive information within JavaScript files. It utilizes asynchronous programming for efficient web crawling and in-depth analysis.</p>

  <img src="https://github.com/dragonked2/Dons/assets/66541902/ad02ae1e-8f30-4ef3-ad35-95735f1cfeb7" alt="Dons Js Scanner">

  <h2>Features</h2>

  <ul>
    <li><strong>Asynchronous Scanning:</strong> Utilizes asyncio and aiohttp for speedy web crawling and JavaScript file analysis.</li>
    <li><strong>Sensitive Information Detection:</strong> Identifies potential sensitive information using pre-defined regex patterns.</li>
    <li><strong>Result Clustering:</strong> Presents cleaner output by clustering similar results.</li>
  </ul>

  <h2>Getting Started</h2>

  <h3>Prerequisites</h3>

  <ul>
    <li>Python 3.7 or higher</li>
    <li>Dependencies: aiohttp, BeautifulSoup, termcolor, tqdm, coloredlogs</li>
  </ul>

  <h3>Installation</h3>

  <ol>
    <li><strong>Clone the repository:</strong>
      <pre><code>git clone https://github.com/dragonked2/Dons.git
cd Dons
      </code></pre>
    </li>
    <li><strong>Install dependencies:</strong>
      <pre><code>pip install -r requirements.txt
      </code></pre>
    </li>
  </ol>

  <h2>Usage</h2>

  <h3>Scan Single Website</h3>

  <pre><code>python main.py
  </code></pre>

  <p>Follow the prompts to enter a single website URL for scanning.</p>

  <h3>Scan Multiple Websites from a File</h3>

  <pre><code>python main.py
  </code></pre>

  <p>Choose the option to scan multiple websites from a file and provide the file path.</p>

  <h3>Customizing Scan Depth</h3>

  <p>You can customize the recursive depth for scanning when prompted. The default depth is set to 4.</p>

  <h2>Results</h2>

  <p>Detected matches will be saved to a file on your desktop and displayed in the console.</p>

  <h2>Example</h2>

  <pre><code>Matches found at https://example.com, JavaScript file: https://example.com/js/main.js:

  Key: Google API Key
    Snippet: AIza...

  Key: Google Cloud Pub/Sub Emulator Host
    Snippet: google.pubsub.emulator.host = 'example.appspot.com'
  </code></pre>

  <h2>Contributions</h2>

  <p>Contributions are always welcome! Feel free to open issues or pull requests.</p>

  <h2>Connect with Me</h2>

  <p><a href="https://www.linkedin.com/in/dragonked2/">Ali Essam - LinkedIn</a></p>

  <h2>License</h2>

  <p>This project is licensed under the MIT License - see the <a href="LICENSE">LICENSE</a> file for details.</p>

  <div align="center">
    <p>Feel free to star ⭐️ the repository if you find it helpful! 🚀</p>
  </div>

</body>

</html>
