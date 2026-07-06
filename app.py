from flask import Flask, render_template, request
from email import policy
from email.parser import BytesParser
import re
import io

try:
    from PIL import Image
except ModuleNotFoundError:
    Image = None

try:
    import pytesseract
except ModuleNotFoundError:
    pytesseract = None

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

ALLOWED_EMAIL_EXTENSIONS = {'eml'}
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'gif'}

SUSPICIOUS_KEYWORDS = [
    'urgent', 'verify', 'account', 'password', 'login', 'confirm', 'update',
    'verify your account', 'security alert', 'click here', 'suspend', 'restricted',
    'payment', 'invoice', 'failed', 'reset', 'verify now'
]

URL_REGEX = re.compile(r'https?://[\w\-./?=&%#]+', re.IGNORECASE)
IP_URL_REGEX = re.compile(r'https?://(?:\d{1,3}\.){3}\d{1,3}(?:[:/\s]|$)')


def allowed_file(filename):
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EMAIL_EXTENSIONS or ext in ALLOWED_IMAGE_EXTENSIONS


def extract_urls(text):
    return URL_REGEX.findall(text or '')


def strip_html_tags(html_text):
    if not html_text:
        return ''
    cleaned = re.sub(r'<[^>]+>', ' ', html_text)
    cleaned = re.sub(r'\s+', ' ', cleaned)
    return cleaned.strip()


def parse_eml(file_bytes):
    try:
        message = BytesParser(policy=policy.default).parsebytes(file_bytes)
    except Exception:
        return None

    headers = {
        'From': message.get('From', ''),
        'To': message.get('To', ''),
        'Subject': message.get('Subject', ''),
        'Date': message.get('Date', ''),
        'Return-Path': message.get('Return-Path', ''),
        'Received': message.get('Received', ''),
    }

    body_text = ''
    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                body_text = part.get_content()
                break
            if content_type == 'text/html' and not body_text:
                body_text = strip_html_tags(part.get_content())
    else:
        if message.get_content_type() == 'text/html':
            body_text = strip_html_tags(message.get_content())
        else:
            body_text = message.get_content()

    return {
        'headers': headers,
        'body': body_text or '',
    }


def ocr_extract_text(file_bytes):
    if Image is None or pytesseract is None:
        return None
    try:
        image = Image.open(io.BytesIO(file_bytes))
        return pytesseract.image_to_string(image)
    except Exception:
        return None


def classify_risk(score):
    if score <= 25:
        return 'Low', 'success'
    if score <= 50:
        return 'Medium', 'warning'
    if score <= 75:
        return 'High', 'danger'
    return 'Critical', 'danger'


def analyze_text(body, headers):
    text = (body or '').lower()
    urls = extract_urls(text)

    risk_score = 5
    reasons = []

    if urls:
        risk_score += min(len(urls) * 6, 30)
        reasons.append(f'Found {len(urls)} URL(s) in the message.')

    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text]
    if keyword_hits:
        risk_score += min(len(keyword_hits) * 4, 24)
        reasons.append('Suspicious phishing keywords detected: ' + ', '.join(sorted(set(keyword_hits))) + '.')

    if IP_URL_REGEX.search(text):
        risk_score += 15
        reasons.append('URL uses a numeric IP address, which is commonly used in phishing.')

    if headers.get('Return-Path') and headers.get('From') and headers['Return-Path'] not in headers['From']:
        risk_score += 12
        reasons.append('Return-Path header does not match the From header.')

    if 'reply-to' in text or 'click here' in text:
        risk_score += 8
        reasons.append('The message contains urgent or click-through instructions.')

    if 'attachment' in text or 'download' in text:
        risk_score += 6
        reasons.append('The email text mentions attachments or downloads.')

    if any(domain in text for domain in ['paypal.com', 'amazon.com', 'google.com', 'microsoft.com']):
        risk_score += 2

    for header_name in ['Subject', 'From', 'To']:
        if headers.get(header_name) and '=?' in headers[header_name]:
            risk_score += 3
            break

    if len(text) < 40:
        risk_score += 5
        reasons.append('Email content appears very short and may be incomplete.')

    risk_score = max(0, min(100, risk_score))
    level, badge = classify_risk(risk_score)

    return {
        'risk_score': risk_score,
        'risk_level': level,
        'badge': badge,
        'urls': urls,
        'reasons': reasons or ['No strong indicators found; the message appears low risk.'],
        'snippet': text[:800] + ('...' if len(text) > 800 else ''),
    }


@app.route('/')
def index():
    return render_template('upload.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    file = request.files.get('file')
    if not file or not file.filename:
        return render_template('upload.html', error='Please upload a valid .eml or image file.')

    if not allowed_file(file.filename):
        return render_template('upload.html', error='Supported file types: .eml, .png, .jpg, .jpeg, .bmp, .gif.')

    file_bytes = file.read()
    ext = file.filename.rsplit('.', 1)[1].lower()

    if ext in ALLOWED_EMAIL_EXTENSIONS:
        parsed = parse_eml(file_bytes)
        if parsed is None:
            return render_template('upload.html', error='Unable to parse the uploaded email file.')

        analysis = analyze_text(parsed['body'], parsed['headers'])
        analysis['headers'] = parsed['headers']
        analysis['file_type'] = 'email'
        analysis['text_source'] = 'Email body'
        return render_template('result.html', analysis=analysis)

    if ext in ALLOWED_IMAGE_EXTENSIONS:
        extracted_text = ocr_extract_text(file_bytes)
        if extracted_text is None:
            return render_template('upload.html', error='OCR is unavailable. Install pillow and pytesseract with Tesseract OCR installed.')

        analysis = analyze_text(extracted_text, {})
        analysis['headers'] = {
            'From': 'N/A',
            'To': 'N/A',
            'Subject': 'N/A',
            'Date': 'N/A',
        }
        analysis['file_type'] = 'image'
        analysis['text_source'] = 'Extracted text from uploaded image'
        return render_template('result.html', analysis=analysis)

    return render_template('upload.html', error='Unsupported file type.')


if __name__ == '__main__':
    app.run(debug=True)
