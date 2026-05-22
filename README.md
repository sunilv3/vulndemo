# VulnDemo

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/sunilv3/vulndemo)

VulnDemo is a deliberately vulnerable web application built with Flask and SQLite, designed for security education, testing, and training purposes. It demonstrates common web application vulnerabilities (including OWASP Top 10) in both a vulnerable state and a secure/mitigated state.

Each vulnerability has a toggle mode, allowing you to switch between **Vulnerable Mode** and **Secure Mode** by appending `?mode=vulnerable` or `?mode=secure` to the URL.

---

## 🌟 Features / Vulnerabilities Included

VulnDemo covers a wide range of security vulnerabilities:

1. **SQL Injection (SQLi)**: Test raw SQL queries vs parameterized queries.
2. **Cross-Site Scripting (XSS)**:
   - Reflected XSS
   - Stored XSS
   - DOM-based XSS
3. **Command Injection**: Run OS commands via unsanitized input vs safe arguments.
4. **Path Traversal**: Read arbitrary files on the system vs secure path validation.
5. **Cross-Site Request Forgery (CSRF)**: Perform state-changing requests with and without CSRF token protection.
6. **Server-Side Request Forgery (SSRF)**: Fetch internal/external URLs vs domain whitelisting.
7. **Insecure Direct Object Reference (IDOR)**: Access other users' profiles via query parameter modification.
8. **XML External Entity (XXE)**: Parse arbitrary XML with external entity resolution enabled vs disabled.
9. **Server-Side Template Injection (SSTI)**: Inject template variables into Jinja2 templates.
10. **Broken Authentication**: Easy SQL injection login and weak password policy vs parameterized authentication and password strength validation.
11. **Unvalidated Redirects and Forwards**: Redirect to arbitrary external sites vs whitelisted host validation.
12. **Insecure Deserialization**: Python `pickle` deserialization vs safe JSON parsing.

---

## 🚀 Getting Started

### Method 1: Local Installation (Python)

Ensure you have Python 3.8+ installed on your system.

1. **Clone the repository:**
   ```bash
   git clone https://github.com/sunilv3/vulndemo.git
   cd vulndemo
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python app.py
   ```

4. **Access the application:**
   Open your browser and navigate to `http://localhost:5000`.

---

### Method 2: Running with Docker

You can run VulnDemo in a containerized environment to keep your host system secure.

1. **Build the Docker Image:**
   ```bash
   docker build -t vulndemo .
   ```

2. **Run the Docker Container:**
   ```bash
   docker run -p 7860:7860 vulndemo
   ```

3. **Access the application:**
   Open `http://localhost:7860` in your web browser.

---

### Method 3: Deploying to Hugging Face Spaces (Free, No Card Required)

You can host this Flask application on Hugging Face Spaces for free using Docker.

1. Create a free account on [Hugging Face](https://huggingface.co/).
2. Click on **Spaces** -> **Create new Space**.
3. Choose a name, select **Docker** as the SDK, and select **Blank** as the template.
4. Clone your new Hugging Face Space repository locally:
   ```bash
   git clone https://huggingface.co/spaces/YOUR_USERNAME/YOUR_SPACE_NAME
   ```
5. Copy all files from this project into your local space directory.
6. Commit and push the files to Hugging Face:
   ```bash
   git add .
   git commit -m "Deploy VulnDemo to Space"
   git push
   ```
7. Your app will automatically build and run live!

---

### Method 4: Deploying to PythonAnywhere (Free, No Card Required)

1. Sign up for a free Beginner account on [PythonAnywhere](https://www.pythonanywhere.com/).
2. Open a **Bash Console** from your dashboard.
3. Clone your GitHub repository:
   ```bash
   git clone https://github.com/sunilv3/vulndemo.git
   ```
4. Navigate to the **Web** tab in your dashboard, click **Add a new web app**, and choose **Manual Configuration** (with Python 3.10).
5. Under **Virtualenv**, create one and install dependencies:
   ```bash
   mkvirtualenv myenv --python=/usr/bin/python3.10
   pip install -r requirements.txt
   ```
6. Edit your WSGI configuration file (link available under the Web tab) to point to your app:
   ```python
   import sys
   path = '/home/YOUR_USERNAME/vulndemo'
   if path not in sys.path:
       sys.path.append(path)
   from app import app as application
   ```
7. Click **Reload** to launch your live application!

---

## 🛡️ Toggle Modes


Switch between security states dynamically in the URL:
- **Vulnerable mode**: Add `?mode=vulnerable` (default)
- **Secure/Protected mode**: Add `?mode=secure`

For example:
- `http://localhost:5000/sql-injection?mode=vulnerable`
- `http://localhost:5000/sql-injection?mode=secure`

---

## ⚠️ Disclaimer

**WARNING:** This application contains intentional security vulnerabilities. Running this application on a public or untrusted network is highly discouraged, as it can expose your host machine to attacks. Use it strictly for local educational and training purposes.
