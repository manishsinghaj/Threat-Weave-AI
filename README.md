PhishGPT-OAuthGuard - Extended PoC (WHOIS, TLS enrichment + UI)
===============================================================

Overview
--------
This extended PoC accepts .eml samples, performs URL evasion + OAuth checks, enriches URLs with WHOIS and TLS certificate info,
and uses your in-house Sage LLM via the SAGE_API to produce a reasoned analysis. It includes a simple Streamlit UI for uploading emails and viewing reports.

Important: copy .env.example -> .env and set SAGE_API_KEY before running Streamlit app or CLI analysis.

Quickstart (Linux / macOS)
--------------------------
1. Unzip the archive
2. Create venv and install deps:
   python3 -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
3. Copy .env.example to .env and edit:
   cp .env.example .env
   # open .env and set SAGE_API_KEY to your developer token
4. Run the Streamlit UI:
   streamlit run app_streamlit.py
5. Or run CLI analysis for a sample EML:
   python cli_analyze.py samples/sample_email.eml

Files of interest
-----------------
- app_streamlit.py        # Streamlit UI for upload + analysis
- cli_analyze.py          # CLI runner to analyze an .eml file
- modules/                # core modules: parser, url analyzer, whois, tls, llm, report
- samples/sample_email.eml
- .env.example

Where to add Sage API key
-------------------------
Edit the .env file and set:
SAGE_API_KEY=YOUR_DEVELOPER_TOKEN
SAGE_API_URL=https://api.sage.cudasvc.com/openai/chat/completions

Notes
-----
- This is a PoC. For production, run the LLM in an approved environment, redact PII before sending to external APIs, and secure the .env.
- WHOIS queries may be rate-limited by your network and the public WHOIS providers.
