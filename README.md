# BrowserTrace DFIR

BrowserTrace DFIR is a forensic-safe browser artifact triage tool designed for digital forensics, incident response and security investigations.

# Forensic Report Example


<img width="1601" height="903" alt="gfdhgghddhdhgdghdhd" src="https://github.com/user-attachments/assets/3b61ee83-5f66-4035-adcf-81d0fdc4fd63" />


The tool automatically discovers browser profiles, safely acquires key artifacts and produces structured investigation outputs including timelines, domain analysis and evidence graphs.

BrowserTrace focuses on triage and investigative visibility, while avoiding extraction of sensitive credential material such as stored passwords or cookies.

# Key Features

• Multi-browser artifact discovery
• Forensic-safe artifact acquisition
• SHA256 hashing of collected files
• Browser history extraction
• Download activity reconstruction
• Bookmark extraction
• Extension discovery
• Investigation timeline generation
• Evidence relationship graph
• Heuristic domain risk analysis
• JSON and HTML forensic reports

# Supported Browsers

BrowserTrace supports both Chromium-based browsers and Firefox.

Chromium family:

Google Chrome

Microsoft Edge

Brave Browser

Opera

Opera GX

Vivaldi

Chromium

Mozilla family:

Firefox

Forensic Safety

BrowserTrace is designed for triage and investigation, not credential extraction.

The tool does NOT extract or decrypt:

stored passwords

cookies

payment data

browser tokens

Artifacts are acquired through forensic-safe copying and hashed using SHA256.

# Example Execution

<img width="1601" height="903" alt="gfdhgghddhdhgdghdhd" src="https://github.com/user-attachments/assets/728c8674-1c5f-4ae2-a224-f87889dfa111" />

# Output Artifacts
![BrowserTrace Run Example](images/browsertrace_run_example.png)

Running the tool generates a structured investigation folder.

Example:

browsertrace_output/
│
├── manifest.json
├── report.json
├── report.html
│
├── ai_analysis.json
│
├── timeline.json
├── timeline.html
│
├── graph.json
└── graph.html
Investigation Views
HTML Forensic Report

# Provides an overview of:

browser profiles

visited domains

downloads

bookmarks

installed extensions

suspicious domain indicators

Timeline Reconstruction
timeline.html


## Investigation Timeline
BrowserTrace reconstructs a chronological timeline of browser activity including visited pages and downloads.

<img width="1370" height="822" alt="ghfghfghfhdkdk" src="https://github.com/user-attachments/assets/2205fe4f-9e2e-45d3-babd-ceb7f91475d8" />


# Chronological reconstruction of:

visited pages

downloads

investigative browsing activity

Useful for:

incident response

user activity reconstruction

threat hunting

# Evidence Graph
graph.html
BrowserTrace builds an investigation graph connecting user, browsers, profiles, domains, extensions and downloads.


<img width="1583" height="919" alt="sghfsjhfsjhfshfjshfjs" src="https://github.com/user-attachments/assets/d4623ee2-efce-47f5-abbd-4b9276aae275" />

# Interactive visualization connecting:

User
 ↓
Browser
 ↓
Profile
 ↓
Domains
 ↓
Extensions
 ↓
Downloads

This allows investigators to quickly identify relationships between artifacts.

# AI Domain Heuristic Analysis
ai_analysis.json

Domains are scored using heuristic indicators such as:

brand impersonation patterns

suspicious keywords (login, auth, verify, secure)

abnormal hostname structure

suspicious TLDs

deep subdomain chains

# Classification levels:

safe
unknown
review
suspicious
Installation

BrowserTrace requires Python 3.10 or later.

No external dependencies are required.

Clone the repository:

git clone https://github.com/YOUR_USERNAME/browsertrace-dfir.git

Move into the project folder:

cd browsertrace-dfir
Usage

# Run the tool directly with Python.

python browsertrace_dfir.py --output-dir browsertrace_output
Command Line Options
Scan all browsers (default)
python browsertrace_dfir.py --output-dir browsertrace_output
Scan only Chromium browsers
python browsertrace_dfir.py --browser chromium
Scan only Firefox
python browsertrace_dfir.py --browser firefox
Limit number of processed profiles
python browsertrace_dfir.py --limit-profiles 2
Example Output
[+] BrowserTrace DFIR completed
[+] Output directory : browsertrace_output
[+] Manifest : browsertrace_output/manifest.json
[+] JSON report : browsertrace_output/report.json
[+] HTML report : browsertrace_output/report.html
[+] AI analysis : browsertrace_output/ai_analysis.json
[+] Timeline JSON : browsertrace_output/timeline.json
[+] Timeline HTML : browsertrace_output/timeline.html
[+] Graph JSON : browsertrace_output/graph.json
[+] Graph HTML : browsertrace_output/graph.html
[+] Profiles scanned : 3
Typical Investigation Use Cases

# BrowserTrace DFIR can be used for:

• incident response triage
• malware infection investigation
• phishing activity investigation
• insider threat analysis
• browser-based attack analysis
• digital forensic artifact reconstruction

Example Investigation Scenario

An analyst suspects a phishing attack was triggered through a browser session.

BrowserTrace can quickly reconstruct:

visited phishing domain

user authentication attempt

downloaded payload

browser extension installation

All artifacts are correlated in timeline and graph views.

# Limitations

BrowserTrace is designed for triage, not full forensic acquisition.

It does not perform:

memory analysis

network capture

credential extraction

full disk forensics

For deeper analysis it should be combined with professional DFIR frameworks.

# License

MIT License

# Disclaimer

This tool is intended for authorized digital forensics, incident response and security investigations only.

The author is not responsible for misuse of this software.

# Author
Neurone4444

BrowserTrace DFIR
Digital Forensics / Security Research Tool
