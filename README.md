# PhishGuard

A lightweight Flask website for phishing email analysis that accepts `.eml` files or uploaded email screenshots.

An intelligent email phishing detection platform built with Flask and Python. It analyzes email headers, URLs, attachments, and message content using machine learning and security rules to detect phishing attempts and generate comprehensive threat reports.

## Features

- Direct `.eml` email upload
- Image upload for screenshots via OCR
- No login required
- No database required
- Instant phishing risk scoring
- Clean, mobile-friendly interface

## Project Structure

- `app.py` — main Flask application
- `requirements.txt` — Python dependencies
- `templates/` — HTML templates
- `static/css/` — custom styling

## Setup

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## Notes

- Image OCR requires Tesseract OCR installed on your machine.
- `.eml` files are parsed directly and no data is stored.

