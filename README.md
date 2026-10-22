# PHISHING-ANALYZER

An offline triage tool for suspicious emails. Give it an `.eml` file and it tells you how risky the message looks and exactly why. It uses only the Python standard library, never opens links or downloads anything, and defangs every link in its output.

## What it checks

| Area | Examples of what it flags |
|------|---------------------------|
| **Sender** | Reply-To or Return-Path on a different domain than From, brand names ("PayPal") sent from the wrong domain, lookalike domains (`paypa1`), mismatched Message-ID |
| **Authentication** | SPF, DKIM and DMARC results from the headers (`fail`, `softfail`, `none`, missing) |
| **Links** | Link text that shows one site but goes to another, raw IP addresses, URL shorteners, punycode, `user@host` tricks, plain `http`, TLDs common in abuse |
| **Attachments** | Double extensions (`invoice.pdf.exe`), executables, scripts, macro documents, archives. Gives each file's SHA-256 |
| **Content** | Pressure and urgency wording ("verify within 24 hours") |
| **Routing** | Number of mail hops and the first public IP the message came from |

## Requirements

Python 3.8 or newer. No packages to install. It runs fully offline.

## Usage

Save the suspicious email as an `.eml` file (in most mail apps: open the message, then use "Download message" or "Save as .eml"). Then run:

```bash
python3 phishing_analyzer.py suspicious.eml
```

Read from standard input with `-`:

```bash
cat suspicious.eml | python3 phishing_analyzer.py -
```

Get machine-readable output:

```bash
python3 phishing_analyzer.py suspicious.eml --json
```

### Try it with the included samples

Both samples are fictional, so every name, domain and IP in them is made up.

```bash
python3 phishing_analyzer.py samples/sample_phishing.eml
python3 phishing_analyzer.py samples/sample_legit.eml
```

The phishing sample scores 100/100 (HIGH RISK) and the legitimate one scores 0/100 (LOW RISK).

## Reading the result

```
VERDICT: HIGH RISK  (score 100/100)

WHY:
  +40  [attachments] Double extension 'invoice.pdf.exe' disguises an executable file
  +35  [links] Link text shows www[.]paypal[.]com but goes to paypa1-secure[.]top
  +20  [auth] SPF result: fail
```

Each finding adds points, capped at 100:

| Score | Verdict |
|-------|---------|
| 0 to 19 | LOW RISK |
| 20 to 49 | SUSPICIOUS |
| 50 and up | HIGH RISK |

The exit code is `0` for LOW RISK and SUSPICIOUS, and `2` for HIGH RISK, so scripts can react to it.

## Using it from Python

```python
from phishing_analyzer import analyze

with open("suspicious.eml", "rb") as fh:
    result = analyze(fh.read())
print(result["verdict"], result["score"])
```

## Limitations

- It scores what is in the file. It does not check whether a domain is new or on a blocklist, because it makes no network requests.
- Authentication results are read from the headers. Headers can be forged before they reach you, so trust results added by your own mail server.
- The brand list is small, and the "organizational domain" logic is simplified.
- A low score is not proof of safety. Treat the verdict as a lead, then confirm with your own tools.

## Safety

Never open links or attachments from a suspicious email on a machine you care about. Share indicators in their defanged form.
