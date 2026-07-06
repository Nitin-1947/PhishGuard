# PhishGuard

A lightweight Flask website for phishing email analysis that accepts `.eml` files or uploaded email screenshots.

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

## Recommended GitHub Upload

1. Create a new GitHub repository.
2. Add the remote URL:

   ```bash
git remote add origin https://github.com/<your-username>/<your-repo>.git
```

3. Push your code:

   ```bash
git add .
git commit -m "Initial commit"
git branch -M main
git push -u origin main
```
