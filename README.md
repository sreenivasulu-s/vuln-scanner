# Nayak The Hacker — Authorized Web Security Scanner

An authorized web security assessment platform for reconnaissance, vulnerability scanning, finding classification, evidence collection, and security reporting.

> **Important:** Use this project only against systems you own or have explicit permission to assess.

## Features

- Authorized web application scanning
- Reconnaissance and VAPT workflow
- Security finding classification
- Evidence collection
- Security reports
- Scan history and findings APIs
- FastAPI backend
- Web frontend
- Automated regression tests

## Project Structure

```text
vuln-scanner/
├── backend/
│   ├── bugbounty/
│   ├── scanner/
│   ├── main.py
│   └── db.py
├── frontend/
├── requirements.txt
├── vuln-scanner-core.txt
├── .gitignore
└── README.md
```

## Local Development

```bash
pip install -r requirements.txt
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

API documentation: `http://127.0.0.1:8000/docs`

## Testing

```bash
pytest -q
```

## Security and Responsible Use

Use this scanner only for authorized security testing. Always obtain explicit authorization, define a narrow scope, avoid destructive testing, protect scan evidence, and responsibly disclose confirmed vulnerabilities.

## Limitations

Scanner output is assessment evidence and should be manually validated before remediation or disclosure decisions.

## License

No license has been published yet. Until a license is added, default copyright terms apply.

## Project

**Nayak The Hacker — Authorized Web Security Scanner**

Repository: https://github.com/sreenivasulu-s/vuln-scanner
