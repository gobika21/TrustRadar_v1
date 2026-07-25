# TrustRadar

TrustRadar is an AI-assisted job scam detection workbench for job descriptions, recruiter messages, screenshots, posting URLs, and company/recruiter websites.

## Stack

- Backend: FastAPI
- Frontend: React + Vite
- Verification: live URL fetch, DNS lookup, RDAP/domain checks, and DuckDuckGo web result parsing

## Run Locally

Backend:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal. The frontend expects the backend at `http://127.0.0.1:8000`.

## Notes

Screenshot uploads are supported in v1, but OCR is not bundled. The app records the file as evidence and analyzes any accompanying text or URLs. Add OCR later with a service such as Google Vision, AWS Textract, or local Tesseract.
