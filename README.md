# ThreatLens 🛡️

AI-powered threat intelligence analysis. Enter an IP address, domain, or URL and ThreatLens
queries VirusTotal and WHOIS, then uses Groq (Llama 3.3 / gpt-oss-20b) to turn the raw evidence
into a plain-English verdict, risk score, and recommended action — tailored to your knowledge level.

## Files in this repo
```
app.py             # Streamlit UI + Groq call + orchestration
sources.py         # IOC validation + VirusTotal/WHOIS lookups
requirements.txt   # Python dependencies
README.md          # This file
```

Note: there is **no `secrets.toml` file included on purpose** — it holds private API keys and
should never be shared or committed. You create it yourself locally (step 2 below).

## Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Create your secrets file
Streamlit reads API keys from `.streamlit/secrets.toml`, which does not exist yet. Create it:

```bash
mkdir .streamlit
```

Then create a file named `.streamlit/secrets.toml` with this content:

```toml
[api_keys]
virustotal = "your-virustotal-api-key-here"
groq = "your-groq-api-key-here"
```

Get your own keys here:
- VirusTotal: https://www.virustotal.com/gui/my-apikey
- Groq: https://console.groq.com/keys

**Never commit this file to GitHub.** If you're pushing this project to a repo, add a
`.gitignore` with the line `.streamlit/secrets.toml` before your first commit.

### 3. Run the app
```bash
streamlit run app.py
```
It opens automatically at `http://localhost:8501`.

## How it works
1. You enter an IP / domain / URL and pick a knowledge level (Beginner/Intermediate/Expert).
2. `sources.py` validates the input and queries VirusTotal + WHOIS.
3. `app.py` builds a prompt from that evidence and sends it to Groq's Llama 3.3 model.
4. The AI's JSON response (verdict, risk score, findings, recommended action) is rendered
   as a dashboard, alongside the raw source data.

If a key is missing or invalid, the app shows a clear error for that source instead of crashing.
