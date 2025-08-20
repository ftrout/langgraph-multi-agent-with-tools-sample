## Multi-Agent Orchestration with LangGraph

This Python script implements a multi-agent system using LangGraph to assess whether a URL is malicious by leveraging threat intelligence from VirusTotal and AlienVault OTX APIs. The system integrates these APIs with a language model (Grok-3 from xAI) to analyze and classify URLs as Malicious, Suspicious, or Benign.

### Features
- **Multi-Agent Workflow**: Uses LangGraph to orchestrate two ReAct agents that query VirusTotal and OTX APIs in parallel, followed by a conclusion step.
- **Threat Intelligence**:
  - **VirusTotal**: Checks URL reputation, malicious/suspicious/harmless detections, and categories.
  - **AlienVault OTX**: Retrieves pulse count and threat indicators.
- **Robust Error Handling**: Validates URLs, retries failed API calls (using `tenacity`), and propagates errors through the workflow.
- **Conclusion Logic**: Classifies URLs based on explicit rules (e.g., Malicious if VirusTotal malicious > 0 or OTX pulse_count > 1).
- **Configurable**: Supports custom model names via environment variables.
- **Secure**: Loads API keys from a `.env` file to prevent hardcoding sensitive information.

### Prerequisites
- Python 3.13+
- Required packages: `langchain`, `langgraph`, `langchain-xai`, `requests`, `tenacity`, `python-dotenv`, `typing_extensions`
- API keys for:
  - [xAI (for Grok-3)]("https://x.ai/api")
  - [VirusTotal]("https://www.virustotal.com/gui/join-us")
  - [AlienVault OTX]("https://otx.alienvault.com/api")

### Setup
1. Install dependencies:
   ```bash
   pip install langchain langgraph langchain-xai requests tenacity python-dotenv typing_extensions
   ```
2. Create a `.env` file with your API keys:
   ```
   XAI_API_KEY=your_xai_key
   VIRUSTOTAL_API_KEY=your_vt_key
   OTX_API_KEY=your_otx_key
   MODEL_NAME=grok-3  # Optional, defaults to grok-3
   ```
3. Run the script:
   ```bash
   python langgraph-multi-agent.py
   ```
4. Enter a URL (e.g., `https://example.com`) when prompted.

### How It Works
1. **Input Validation**: Ensures the provided URL is valid (includes scheme and domain).
2. **Parallel API Calls**: Two agents query VirusTotal and OTX APIs concurrently to fetch threat intelligence.
3. **Conclusion**: A language model processes the API results, classifying the URL as Malicious, Suspicious, or Benign based on predefined rules.
4. **Output**: Displays the URL, API results, conclusion, and any errors.

### Example Output
```
URL: https://example.com
VirusTotal Result: I've checked the URL https://example.com using VirusTotal, and here are the results:

- Malicious: 0
- Suspicious: 0
- Harmless: 70
- Undetected: 27
- Reputation: 42

Categories associated with the URL:
- Information Technology (alphaMountain.ai)
- Computers and Software (BitDefender)
- Content Server (Xcitium Verdict Cloud)
- Information Technology (Sophos)
- Information Technology (Forcepoint ThreatSeeker)

Based on this data, the URL appears to be safe with no malicious or suspicious activity reported. If you have any further questions or need additional analysis, let me know!
OTX Result: I've retrieved threat intelligence data for the URL https://example.com from the AlienVault OTX API. Here's a summary of the findings:

- Pulse Count: There are 13 pulses associated with this URL, indicating it has been flagged in multiple threat intelligence reports.
- Key Pulses: 
  - Several pulses highlight potential malicious activity linked to the URL, including associations with malware, botnets, and suspicious behaviors. Notable mentions include campaigns like "Sign in to your account - Anorocuriv," "Sinkhole | Win32/Dofoil.R CnC Beacon," and others related to various malware families such as Mirai, PrivateLoader, and more.
  - Specific threats include connections to trojans, spyware, and remote access tools, as well as tactics like obfuscation, process discovery, and execution guardrails (e.g., MITRE ATT&CK IDs T1027, T1057, T1480).
- Malware Families: The URL is linked to several malware families across the pulses, including Win.Trojan, Mirai, Amadey, Cobalt Strike, and others.
- Attack Techniques: Common attack techniques associated with this URL include Ingress Tool Transfer (T1105), Application Layer Protocol (T1071), and Dynamic Resolution (T1568), among others.
- Industries Targeted: Some pulses indicate targeting of industries such as Technology, Telecommunications, Government, and Civil Society.
- Adversaries: One pulse mentions the "DragonForce Malaysia Hacker Group" as a potential adversary.

Conclusion: The URL https://example.com appears to be associated with significant malicious activity based on the AlienVault OTX data. It has been linked to multiple threat campaigns, malware families, and attack techniques. If this URL is encountered in your environment, it is recommended to treat it as high-risk and initiate a thorough investigation or incident response process to mitigate potential threats. 

If you have further questions or need additional analysis on specific pulses or indicators, please let me know.
Conclusion: **Conclusion: Malicious**

Reasoning: Based on the provided threat intelligence data and the classification criteria, the URL https://example.com is classified as Malicious. The AlienVault OTX data indicates a pulse count of 13, which is significantly greater than 1, meeting the threshold for a Malicious classification. Although the VirusTotal results show no malicious or suspicious detections (0 for both), the OTX data's strong association with multiple threat campaigns, malware families, and attack techniques outweighs the VirusTotal findings under the given criteria. Therefore, the URL is deemed high-risk and should be treated with caution.

Note on Errors: There are no apparent errors in the results provided. However, there is a discrepancy between the VirusTotal and OTX findings, with VirusTotal indicating no malicious activity and OTX showing significant threat associations. As per the classification rules, the conservative approach is to prioritize the OTX pulse count, leading to a Malicious classification.
```

### Notes
- Ensure `.env` is excluded from version control (e.g., add to `.gitignore`).
- The script uses LangGraph’s default ReAct prompt for agent tool invocation.
- Parallel execution may require sufficient API rate limits.
- For debugging, enable logging:
  ```python
  import logging
  logging.basicConfig(level=logging.DEBUG)
  ```

### Troubleshooting
- **Invalid API Keys**: Verify keys in `.env` and test API endpoints independently.
- **LangGraph Errors**: Ensure the latest `langgraph` version is installed (`pip install -U langgraph`).
- **URL Issues**: Provide URLs with proper format (e.g., `https://example.com`).

---

This summary is designed to be concise yet comprehensive, covering setup, usage, and key details for users. You can add it directly to your README file. If you want to include additional sections (e.g., contributing guidelines, license, or specific error handling details), let me know, and I can expand it!