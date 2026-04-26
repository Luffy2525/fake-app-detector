# 🛡 ShieldScan — Fake App & Dark Pattern Detection System

A full-stack web application that analyzes Android APK files and app metadata to detect:
- **Module 1**: APK structure and preprocessing
- **Module 2**: Permission risk analysis
- **Module 3**: Dark pattern detection (UI deception)
- **Module 4**: Fake app identification

---

## 📁 Project Structure

```
fake-app-detector/
├── backend/
│   ├── __init__.py
│   └── app.py              ← Flask API (all 4 modules)
├── frontend/
│   ├── index.html          ← Main website
│   └── static/
│       ├── css/style.css
│       └── js/main.js
├── uploads/                ← Temp APK storage (auto-created)
├── reports/                ← JSON reports (auto-created)
├── requirements.txt
├── render.yaml             ← Render deployment config
├── Procfile
└── README.md
```

---

## 🚀 LOCAL SETUP (Run on Your Laptop)

### Step 1 — Prerequisites
Make sure you have Python 3.9+ installed:
```bash
python --version    # Should be 3.9 or higher
pip --version
```

### Step 2 — Clone / Download the Project
```bash
# If using Git:
git clone https://github.com/YOUR_USERNAME/shieldscan.git
cd shieldscan

# Or just navigate to the project folder:
cd fake-app-detector
```

### Step 3 — Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Mac / Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 4 — Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 5 — Run the Application
```bash
python backend/app.py
```

You should see:
```
* Running on http://0.0.0.0:5000
* Debug mode: on
```

### Step 6 — Open in Browser
Visit: **http://localhost:5000**

---

## 🌐 DEPLOY ON RENDER (Free Cloud Hosting)

### Step 1 — Push to GitHub

1. Create a GitHub account at https://github.com
2. Create a new repository called `shieldscan`
3. Run these commands in your project folder:

```bash
git init
git add .
git commit -m "Initial commit — ShieldScan"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/shieldscan.git
git push -u origin main
```

### Step 2 — Create Render Account
1. Go to **https://render.com**
2. Sign up with GitHub (free tier available)

### Step 3 — Deploy Web Service
1. Click **"New +"** → **"Web Service"**
2. Connect your GitHub repository
3. Configure:
   - **Name**: `shieldscan`
   - **Runtime**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn backend.app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120`
   - **Instance Type**: Free

4. Add Environment Variable:
   - Key: `DEBUG`  Value: `false`

5. Click **"Create Web Service"**

### Step 4 — Get Your Live URL
After ~3-5 minutes, Render gives you a URL like:
```
https://shieldscan.onrender.com
```

Your app is now live! ✅

---

## 📡 API ENDPOINTS

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Main website |
| POST | `/api/analyze` | Upload & analyze APK file |
| POST | `/api/analyze-url` | Analyze by app name/URL |
| GET | `/api/stats` | Get platform statistics |
| GET | `/api/health` | Health check |

### Example API call (analyze by URL):
```bash
curl -X POST https://your-app.onrender.com/api/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"app_name":"WhatsApp Plus","developer":"Unknown Dev","description":"Free unlimited subscription auto-renews cancel anytime"}'
```

---

## 🔬 Module Details

### Module 1 — APK Preprocessing
- Validates ZIP/APK format
- Computes MD5 and SHA-256 file hashes
- Reads AndroidManifest.xml structure
- Detects DEX bytecode and native libraries
- Extracts internal file list

### Module 2 — Permission Analysis
- Maps 30+ Android permissions against risk database
- Categorizes: HIGH / MEDIUM / LOW / UNKNOWN
- Computes 0–100 permission risk score
- Flags dangerous permissions: SMS, CALL, OVERLAY, ACCESSIBILITY

### Module 3 — Dark Pattern Detection
Detects 10 dark pattern categories:
- Hidden costs / forced continuity
- Trick questions
- Confirmshaming
- Urgency/pressure tactics
- Roach motel (hard to cancel)
- Privacy zuckering
- Misdirection
- Basket sneaking
- Disguised ads
- Misleading pricing

### Module 4 — Fake App Detection
- Hash check against known malware signatures
- Cloned app name detection (WhatsApp Pro, Instagram Plus, etc.)
- Malicious APK distribution domain blacklist
- Suspicious developer pattern matching
- Overlay attack and accessibility abuse flags

---

## 🧪 Testing the System

### Test with a real APK:
Download any free APK from F-Droid (open source store), upload it to test real analysis.

### Test URL Analysis:
Enter app name: `WhatsApp Plus`
Developer: `Unknown Developer`
Description: `Free unlimited subscription auto-renews cancel anytime first month free`

Expected result: SUSPICIOUS or DANGEROUS with dark patterns detected.

---

## ⚙️ Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3, Flask, Flask-CORS |
| APK Parsing | zipfile, hashlib, re |
| Frontend | HTML5, CSS3 (Custom), Vanilla JS |
| Fonts | Space Mono, Syne (Google Fonts) |
| Deployment | Render (gunicorn) |
| File Handling | werkzeug secure upload |

---

## 📝 Notes for Presentation

1. The system works with REAL APK files — test with any `.apk` file
2. URL/metadata analysis works entirely without APK — good demo
3. Dark pattern detection uses NLP keyword matching on text
4. The permission database covers all major Android dangerous permissions
5. All 4 modules are clearly separated in `backend/app.py`

---

Built as Mini Project — Fake App & Dark Pattern Detection System
