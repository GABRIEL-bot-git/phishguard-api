import mysql.connector
import bcrypt
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import pandas as pd
import re
import os
from dotenv import load_dotenv

load_dotenv()

# Initialize the FastAPI Application
app = FastAPI(
    title="Phishing Detection AI API",
    description="Backend API for hybrid URL and SMS threat detection.",
    version="1.0.0"
)

# Enable CORS so the Mobile Frontend can communicate with this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to your mobile app's domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load the AI Models (Ensure your .pkl files are in the same directory)
try:
    rf_model = joblib.load('url_random_forest_model.pkl')
    xgb_model = joblib.load('sms_xgboost_model.pkl')
    tfidf = joblib.load('sms_tfidf_vectorizer.pkl')
    print("AI Models loaded successfully into memory.")
except Exception as e:
    print(f"CRITICAL ERROR loading models: {e}. Ensure .pkl files are in the backend_api folder.")

# Define the Pydantic Data Models for the incoming JSON requests
class URLPayload(BaseModel):
    url: str

class SMSPayload(BaseModel):
    message: str

class RegisterPayload(BaseModel):
    full_name: str
    email: str
    password: str

class LoginPayload(BaseModel):
    email: str
    password: str


def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        port=int(os.getenv("DB_PORT")), 
        database=os.getenv("DB_NAME")
    )

# Helper Functions (Replicated from our Colab training script)
def extract_url_features(url):
    """Decomposes a URL into numerical lexical features."""
    return {
        'url_length': len(url),
        'num_digits': sum(c.isdigit() for c in url),
        'num_special_chars': len(re.findall(r'[@\-\?=\.]', url)),
        'has_ip': 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
        'has_http': 1 if 'http://' in url else 0,
        'has_https': 1 if 'https://' in url else 0
    }

def clean_text(text):
    """Standardizes SMS text for NLP analysis."""
    text = text.lower()
    text = re.sub(r'\W', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

# --- API Endpoints ---

@app.post("/api/v1/scan/url")
def scan_url(payload: URLPayload):
    try:
        features = extract_url_features(payload.url)
        df_features = pd.DataFrame([features])
        
        prediction = rf_model.predict(df_features)[0]
        prob_array = rf_model.predict_proba(df_features)[0]
        threat_probability = prob_array[1] * 100
        
        status = "Phishing" if prediction == 1 else "Safe"
        prob_str = f"{threat_probability:.2f}%"
        
        # --- NEW: Save the scan to the database ---
        conn = get_db_connection()
        cursor = conn.cursor()
        sql = """INSERT INTO tbl_scan_logs 
                 (user_id, payload_type, payload_content, threat_probability, classification) 
                 VALUES (%s, %s, %s, %s, %s)"""
        # Note: We are using a default user_id of 1 for now until we link the mobile tokens
        cursor.execute(sql, (1, 'URL', payload.url, prob_str, status))
        conn.commit()
        cursor.close()
        conn.close()
        # ------------------------------------------

        return {
            "target": payload.url, 
            "classification": status, 
            "threat_probability": prob_str
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/scan/sms")
def scan_sms(payload: SMSPayload):
    try:
        cleaned_msg = clean_text(payload.message)
        vectorized_msg = tfidf.transform([cleaned_msg]).toarray()
        
        prediction = xgb_model.predict(vectorized_msg)[0]
        prob_array = xgb_model.predict_proba(vectorized_msg)[0]
        threat_probability = prob_array[1] * 100
        
        status = "Phishing" if prediction == 1 else "Safe"
        prob_str = f"{threat_probability:.2f}%"
        
        # --- NEW: Save the scan to the database ---
        conn = get_db_connection()
        cursor = conn.cursor()
        sql = """INSERT INTO tbl_scan_logs 
                 (user_id, payload_type, payload_content, threat_probability, classification) 
                 VALUES (%s, %s, %s, %s, %s)"""
        cursor.execute(sql, (1, 'SMS', payload.message, prob_str, status))
        conn.commit()
        cursor.close()
        conn.close()
        # ------------------------------------------

        return {
            "target": payload.message, 
            "classification": status, 
            "threat_probability": prob_str
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/auth/register")
def register_user(payload: RegisterPayload):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Native bcrypt implementation
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(payload.password.encode('utf-8'), salt).decode('utf-8')
        
        sql = "INSERT INTO tbl_users (full_name, email, password_hash) VALUES (%s, %s, %s)"
        cursor.execute(sql, (payload.full_name, payload.email, hashed_password))
        conn.commit()
        
        return {"message": "User registered successfully"}
    except mysql.connector.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already exists")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

@app.post("/api/v1/auth/login")
def login_user(payload: LoginPayload):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        sql = "SELECT * FROM tbl_users WHERE email = %s"
        cursor.execute(sql, (payload.email,))
        user = cursor.fetchone()
        
        # 1. Check if user exists
        if not user:
            raise HTTPException(status_code=401, detail="Invalid email or password")
            
        # 2. Check if password matches the hash
        is_valid = bcrypt.checkpw(payload.password.encode('utf-8'), user['password_hash'].encode('utf-8'))
        
        if not is_valid:
            raise HTTPException(status_code=401, detail="Invalid email or password")
            
        return {"message": "Login successful", "user_id": user['user_id'], "name": user['full_name']}
    except Exception as e:
        if isinstance(e, HTTPException): raise e
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

@app.get("/api/v1/admin/logs")
def get_all_logs():
    """Retrieves all scan logs and user details for the Admin Dashboard."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        sql = """
            SELECT 
                s.log_id, 
                u.full_name, 
                s.payload_type, 
                s.payload_content, 
                s.threat_probability, 
                s.classification, 
                s.scan_time 
            FROM tbl_scan_logs s
            JOIN tbl_users u ON s.user_id = u.user_id
            ORDER BY s.scan_time DESC
        """
        cursor.execute(sql)
        logs = cursor.fetchall()
        
        return {"total_scans": len(logs), "logs": logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()
