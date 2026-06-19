# Cyber Shield AI — Flask Version

## Project structure
```
cyber_shield_flask/
├── app.py
├── requirements.txt
├── static/
│   ├── style.css
│   └── script.js
└── templates/
    ├── base.html
    ├── index.html
    ├── about.html
    └── contact.html
```

## Run it

1. (Optional) Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   ```

2. Install Flask:
   ```
   pip install -r requirements.txt
   ```

3. Start the dev server:
   ```
   python app.py
   ```

4. Open http://127.0.0.1:5000 in your browser.

## Notes on the conversion
- The three HTML pages now share a single `templates/base.html` layout (nav + footer), so each page template only contains its unique content. The "active" nav link is set via the `active_page` variable passed from each route.
- CSS and JS are served from `static/` using Flask's `url_for('static', filename=...)` instead of relative paths.
- The contact form now POSTs to `/contact` and is handled by a real Flask route (`app.py`) instead of a JS-only `alert()`. It currently just prints the submission to the console — wire it up to a database or email service when you're ready.
- "SCAN LINK NOW" still links out to `https://cybersalmanproject.netlify.app` as in the original.
