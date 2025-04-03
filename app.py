from flask import Flask, request, jsonify, render_template, send_from_directory
import re
import os
import json
import sqlite3
import hashlib
from datetime import datetime, timedelta
import urllib.parse
import random
import string
from flask_cors import CORS
import ipaddress
import tldextract

app = Flask(__name__, static_folder='static')
CORS(app)  # Enable CORS for all routes

# Configuration
DATABASE_FILE = 'spam_database.db'

# Indian phone number regex pattern
INDIAN_PHONE_REGEX = r'^(\+91[\-\s]?)?[0]?(91)?[6789]\d{9}$'

# Initialize database
def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Create tables if they don't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS spam_numbers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone_number TEXT UNIQUE,
        spam_score REAL,
        report_count INTEGER DEFAULT 1,
        first_reported TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_reported TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        spam_type TEXT,
        hash TEXT UNIQUE
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS spam_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone_number TEXT,
        report_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        report_source TEXT,
        report_details TEXT,
        reporter_ip TEXT
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS message_analysis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_hash TEXT UNIQUE,
        is_spam BOOLEAN,
        confidence REAL,
        analysis_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        spam_indicators TEXT
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS phishing_sites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT UNIQUE,
        is_phishing BOOLEAN,
        confidence REAL,
        analysis_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        phishing_indicators TEXT
    )
    ''')
    
    # Load sample Indian spam data if table is empty
    cursor.execute("SELECT COUNT(*) FROM spam_numbers")
    if cursor.fetchone()[0] == 0:
        load_sample_data(cursor)
    
    conn.commit()
    conn.close()

def load_sample_data(cursor):
    # Sample Indian spam numbers with categories
    spam_numbers = [
    # Financial Scams
    ("+919876543201", 0.97, 185, "Scam", "Bitcoin Investment"),
    ("+918765432102", 0.95, 132, "Scam", "Stock Market Tips"),
    ("+917654321023", 0.96, 156, "Scam", "Forex Trading"),
    ("+919765432104", 0.94, 121, "Scam", "Mutual Fund Offer"),
    ("+918654321055", 0.93, 112, "Scam", "Tax Saving Scheme"),

    # Loan/Insurance Frauds
    ("+919876543206", 0.96, 178, "Scam", "Instant Personal Loan"),
    ("+918765432107", 0.92, 98, "Scam", "Credit Card Debt Relief"),
    ("+917654321038", 0.95, 145, "Scam", "Insurance Policy Bonus"),
    ("+919865432109", 0.91, 87, "Scam", "PPF Account Alert"),

    # Government Impersonation
    ("+919712345670", 0.98, 203, "Scam", "Income Tax Refund"),
    ("+918623456781", 0.97, 187, "Scam", "PM Kisan Yojana"),
    ("+917534567892", 0.96, 165, "Scam", "Aadhaar Suspension"),
    ("+919645678903", 0.95, 142, "Scam", "EPF Withdrawal"),

    # Job/Work Scams
    ("+919756789014", 0.97, 192, "Scam", "Data Entry Job"),
    ("+918667890125", 0.94, 136, "Scam", "Amazon Part-Time Work"),
    ("+917578901236", 0.96, 168, "Scam", "Google Work From Home"),

    # E-Commerce Frauds
    ("+919889012347", 0.95, 152, "Scam", "Flipkart Cashback"),
    ("+918790123458", 0.93, 128, "Scam", "Amazon Gift Card"),
    ("+917691234569", 0.94, 138, "Scam", "Mega Shopping Sale"),

    # Utility Payment Scams
    ("+919802345670", 0.96, 174, "Scam", "Electricity Bill Due"),
    ("+918713456781", 0.95, 157, "Scam", "Gas Connection Renewal"),
    ("+917624567892", 0.94, 146, "Scam", "Water Tax Payment"),

    # Tech Support Scams
    ("+919735678903", 0.98, 217, "Scam", "Microsoft Tech Support"),
    ("+918646789014", 0.97, 198, "Scam", "Apple ID Hacked"),
    ("+917557890125", 0.96, 176, "Scam", "WiFi Security Alert"),

    # Newly Emerging Scams (2024)
    ("+919968012345", 0.97, 188, "Scam", "Crypto Wallet Verification"),
    ("+918879123456", 0.95, 162, "Scam", "Metaverse Investment"),
    ("+917780234567", 0.96, 172, "Scam", "AI Trading Bot"),
    ("+919691345678", 0.94, 148, "Scam", "NFT Opportunity")
]
    
    for number, score, count, source, spam_type in sample_data:
        hash_value = hashlib.md5(number.encode()).hexdigest()
        cursor.execute(
            "INSERT OR IGNORE INTO spam_numbers (phone_number, spam_score, report_count, spam_type, hash) VALUES (?, ?, ?, ?, ?)",
            (number, score, count, f"{source}: {spam_type}", hash_value)
        )

# Serve the main HTML file
@app.route('/')
def home():
    return render_template('index.html')  # ✅ Correct path

# API endpoint for checking phone numbers
@app.route('/api/check-number', methods=['POST'])
def check_number():
    data = request.json
    phone_number = data.get('phoneNumber', '')
    
    # Clean the phone number
    phone_number = re.sub(r'\s+|-|$$|$$', '', phone_number)
    
    # Check if it's a valid Indian number
    is_indian = bool(re.match(INDIAN_PHONE_REGEX, phone_number))
    
    if not is_indian and phone_number.startswith('+91'):
        return jsonify({
            'status': 'error',
            'message': 'Invalid Indian phone number format',
            'result_type': 'invalid'
        })
    
    # Check if number exists in database
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT spam_score, report_count, first_reported, spam_type FROM spam_numbers WHERE phone_number = ?", 
                  (phone_number,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        spam_score, report_count, first_reported, spam_type = result
        
        # Format the date
        first_reported_date = datetime.strptime(first_reported, '%Y-%m-%d %H:%M:%S').strftime('%B %d, %Y')
        
        return jsonify({
            'status': 'success',
            'is_spam': spam_score > 0.7,
            'confidence': round(spam_score * 100),
            'result_type': 'spam' if spam_score > 0.7 else 'safe',
            'details': {
                'reported_count': report_count,
                'first_reported': first_reported_date,
                'spam_type': spam_type
            }
        })
    else:
        # If not in database, use pattern-based analysis
        analysis = analyze_number_pattern(phone_number)
        
        return jsonify({
            'status': 'success',
            'is_spam': analysis['is_spam'],
            'confidence': analysis['confidence'],
            'result_type': 'spam' if analysis['is_spam'] else 'safe',
            'details': {
                'analysis': analysis['details'],
                'pattern_based': True
            }
        })

# Pattern-based phone number analysis
def analyze_number_pattern(phone_number):
    # Clean the number
    clean_number = re.sub(r'\D', '', phone_number)
    
    # Initialize variables
    is_spam = False
    confidence = 20
    details = "Number not found in spam database"
    
    # Check for Indian number
    is_indian = bool(re.match(INDIAN_PHONE_REGEX, phone_number))
    
    if is_indian:
        # Extract the last 10 digits (Indian mobile numbers are 10 digits)
        if len(clean_number) > 10:
            clean_number = clean_number[-10:]
        
        # Check for suspicious patterns
        
        # 1. Sequential digits (e.g., 1234567890)
        sequential = True
        for i in range(len(clean_number) - 1):
            if int(clean_number[i+1]) != (int(clean_number[i]) + 1) % 10:
                sequential = False
                break
        
        if sequential:
            is_spam = True
            confidence = 85
            details = "Sequential number pattern detected"
            return {'is_spam': is_spam, 'confidence': confidence, 'details': details}
        
        # 2. Repeated digits (e.g., 9999999999)
        if len(set(clean_number)) <= 2:
            is_spam = True
            confidence = 90
            details = "Repeated digit pattern detected"
            return {'is_spam': is_spam, 'confidence': confidence, 'details': details}
        
        # 3. Patterns like AABBCC (e.g., 9988776655)
        pattern_count = 0
        for i in range(0, len(clean_number), 2):
            if i+1 < len(clean_number) and clean_number[i] == clean_number[i+1]:
                pattern_count += 1
        
        if pattern_count >= 4:
            is_spam = True
            confidence = 75
            details = "Paired digit pattern detected"
            return {'is_spam': is_spam, 'confidence': confidence, 'details': details}
        
        # 4. Check for known Indian spam prefixes
        # These are example prefixes - in a real system, you'd have a more comprehensive list
        spam_prefixes = ['140', '141', '142', '143', '144', '145', '146', '147', '148', '149']
        
        if any(clean_number.startswith(prefix) for prefix in spam_prefixes):
            is_spam = True
            confidence = 80
            details = "Known spam prefix detected"
            return {'is_spam': is_spam, 'confidence': confidence, 'details': details}
        
        # 5. Check for telemarketing series
        # In India, certain number series are allocated to telemarketers
        # This is a simplified example
        if clean_number.startswith('140'):
            is_spam = True
            confidence = 95
            details = "Telemarketing number series detected"
            return {'is_spam': is_spam, 'confidence': confidence, 'details': details}
        
        # 6. Check for common Indian scam number patterns
        # Last 4 digits are same (e.g., xxxx1111)
        if len(set(clean_number[-4:])) == 1:
            is_spam = True
            confidence = 70
            details = "Suspicious last 4 digits pattern"
            return {'is_spam': is_spam, 'confidence': confidence, 'details': details}
        
        # 7. Check operator prefixes for prepaid/promotional numbers
        # This is a simplified check - real implementation would be more comprehensive
        operator_prefixes = {
            # Jio
            '70': 0.3, '89': 0.3, '63': 0.3, '91': 0.3, 
            # Airtel
            '98': 0.3, '99': 0.3, '90': 0.3, '70': 0.3, 
            # Vodafone Idea
            '96': 0.3, '97': 0.3, '98': 0.3, '95': 0.3,
            # BSNL
            '94': 0.2, '99': 0.2, '70': 0.2, '60': 0.2
        }
        
        prefix_2 = clean_number[:2]
        if prefix_2 in operator_prefixes:
            # Slightly increase suspicion for certain operator prefixes
            # This is just a small factor in the overall analysis
            confidence += operator_prefixes[prefix_2]
    
    # For non-Indian numbers, we can do basic pattern analysis
    else:
        # Check for international premium rate numbers
        high_cost_prefixes = ['+1900', '+1976', '+1809', '+1284', '+1473', '+1649', '+1767', '+1849']
        if any(phone_number.startswith(prefix) for prefix in high_cost_prefixes):
            is_spam = True
            confidence = 85
            details = "International premium rate number detected"
            return {'is_spam': is_spam, 'confidence': confidence, 'details': details}
    
    # If we've reached here, no strong spam indicators were found
    # Return a low confidence spam score based on accumulated factors
    if confidence > 50:
        is_spam = True
        details = "Multiple minor suspicious patterns detected"
    else:
        is_spam = False
        confidence = 100 - confidence  # Invert for safe numbers
        details = "No suspicious patterns detected"
    
    return {
        'is_spam': is_spam,
        'confidence': confidence,
        'details': details
    }

# API endpoint for analyzing messages
@app.route('/api/analyze-message', methods=['POST'])
def analyze_message():
    data = request.json
    message = data.get('message', '')
    
    # Create a hash of the message to avoid reanalyzing the same content
    message_hash = hashlib.md5(message.encode()).hexdigest()
    
    # Check if we've already analyzed this message
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT is_spam, confidence, spam_indicators FROM message_analysis WHERE message_hash = ?", 
                  (message_hash,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        is_spam, confidence, spam_indicators = result
        return jsonify({
            'status': 'success',
            'is_spam': bool(is_spam),
            'confidence': confidence,
            'result_type': 'spam' if is_spam else 'safe',
            'details': json.loads(spam_indicators) if spam_indicators else {}
        })
    
    # If not analyzed before, use rule-based analysis
    analysis = analyze_message_content(message)
    
    # Store the analysis result
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO message_analysis (message_hash, is_spam, confidence, spam_indicators) VALUES (?, ?, ?, ?)",
        (message_hash, analysis['is_spam'], analysis['confidence'], json.dumps(analysis['details']))
    )
    conn.commit()
    conn.close()
    
    return jsonify({
        'status': 'success',
        'is_spam': analysis['is_spam'],
        'confidence': analysis['confidence'],
        'result_type': 'spam' if analysis['is_spam'] else 'safe',
        'details': analysis['details']
    })

# Rule-based message content analysis
def analyze_message_content(message):
    # Convert to lowercase for case-insensitive matching
    message_lower = message.lower()
    
    # Initialize scoring variables
    spam_score = 0
    max_score = 100
    detected_issues = []
    
    # 1. Check for common spam keywords
    spam_keywords = spam_keywords = {
    # General spam keywords
    'urgent': 10, 'winner': 15, 'prize': 15, 'million': 10, 'free': 5,
    'password': 10, 'account': 5, 'verify': 5, 'bank': 5, 'click here': 10,
    'limited time': 10, 'offer': 5, 'congratulations': 10, 'credit card': 5,
    'loan': 5, 'investment': 5, 'opportunity': 5, 'discount': 5, 'guaranteed': 10,
    'risk-free': 10, 'act now': 10, 'exclusive': 5, 'hidden charges': 10,

    # Financial scams
    'bitcoin': 10, 'crypto': 10, 'forex': 10, 'stock alert': 10, 'tax refund': 15,
    'inheritance': 15, 'unclaimed money': 15, 'debt relief': 10, 'credit score': 5,
    'social security': 15, 'wealth management': 10, 'gold investment': 10,
    'retirement fund': 10, 'pension plan': 10, 'insurance claim': 10,
    'property investment': 10, 'mutual funds': 10, 'hedge fund': 15,
    'ipo opportunity': 15, 'pre-ipo shares': 20, 'private equity': 15,
    'offshore account': 20, 'tax evasion': 20, 'money transfer': 10,
    'currency exchange': 10, 'asset protection': 15, 'credit repair': 10,
    'loan waiver': 15, 'debt settlement': 10, 'bankruptcy help': 10,
    'frozen funds': 15, 'account verification': 10, 'wire transfer': 15,
    'nigerian prince': 20, 'inheritance tax': 15, 'trust fund': 15,
    'dividend payment': 10, 'bearer bonds': 20, 'swiss account': 20,
    'underground banking': 20, 'cash flipping': 20, 'money laundering': 20,
    'ponzi scheme': 20, 'fake charity': 15, 'recovery scam': 15,

    # Indian-specific spam keywords
    'kyc': 15, 'otp': 10, 'aadhaar': 10, 'pan card': 10, 'income tax': 10,
    'refund': 15, 'lottery': 20, 'lucky draw': 15, 'government scheme': 15,
    'pm scheme': 15, 'subsidy': 15, 'cashback': 10, 'paytm': 5, 'phonepe': 5,
    'upi': 5, 'electricity bill': 10, 'gas subsidy': 15, 'job offer': 15,
    'work from home': 15, 'earning': 10, 'doubling': 20, 'ration card': 10,
    'pf withdrawal': 15,

    # Phishing/Account scams
    'suspended': 10, 'hacked': 10, 'security alert': 10, 'unauthorized login': 15,
    'update account': 10, 'expired': 5, 'verify identity': 10, 'reactivate': 10,
    'account locked': 15, 'password reset': 10, 'login attempt': 15, 'fraud detected': 15,
    'urgent action required': 15, 'confirm your identity': 10, 'billing issue': 10,
    'payment failed': 10, 'subscription renewal': 5, 'unusual activity': 15,
    'security breach': 15, 'restore access': 10, 'verification needed': 10,
    'credentials expired': 10, 'bank alert': 15, 'card blocked': 15, 'account closure': 10,
    'immediate attention': 10, 'critical warning': 15, 'system upgrade': 5,
    'phishing attempt': 20, 'fake invoice': 15, 'urgent verification': 15,
    'data breach': 20, 'compromised account': 15, 'two-factor disabled': 15,
    'recover account': 10, 'suspicious login': 15, 'password change': 10,
    'email verification': 10, 'fraud prevention': 10, 'account recovery': 10,
    'security update': 5, 'profile update': 5, 'identity theft': 20,
    'unauthorized transaction': 20, 'tax refund alert': 15, 'credit limit': 10,
    'social media alert': 10, 'cloud storage alert': 10, 'copyright infringement': 15,
    'domain expiry': 10, 'IT support scam': 20, 'fake tech support': 20,
    'ransomware threat': 20, 'antivirus renewal': 10, 'Windows update scam': 15,  # <-- COMMA ADDED HERE

    # Job/Investment scams
    'earn money': 10, 'part-time job': 10, 'no experience': 10, 'instant income': 15,
    'secret method': 15, 'passive income': 10, 'work from home': 15, 'easy money': 15,
    'quick cash': 15, 'zero investment': 15, 'high returns': 20, 'guaranteed earnings': 20,
    'financial freedom': 15, 'make money online': 15, 'data entry job': 10,
    'home-based job': 15, 'earn daily': 15, 'minimal effort': 15, 'no skills required': 10,
    'direct payment': 10, 'international offer': 15, 'urgent hiring': 10, 'immediate start': 10,
    'unlimited income': 20, 'double your money': 20, 'cash reward': 10, 'referral income': 10,
    'online business': 15, 'tax-free earnings': 15, 'secret formula': 20, 'exclusive offer': 15,
    'hidden opportunity': 15, 'government job': 15, 'fake recruiter': 20, 'pay for training': 15,
    'advance fee': 20, 'commission-based': 10, 'mystery shopping': 10, 'fake internship': 15,
    'pyramid scheme': 20, 'multi-level marketing': 15, 'trading scam': 20, 'fake scholarship': 15
}
    
    
    found_keywords = []
    for keyword, score in spam_keywords.items():
        if keyword in message_lower:
            spam_score += score
            found_keywords.append(keyword)
    
    if found_keywords:
        detected_issues.append(f"Contains spam keywords: {', '.join(found_keywords)}")
    
    # 2. Check for urgency indicators
    urgency_phrases = [
        'act now', 'limited time', 'expires soon', 'today only', 'last chance',
        'hurry', 'don\'t miss', 'immediately', 'urgent', 'expiring', 'deadline',
        'quickly', 'fast', 'now', 'instant'
    ]
    
    urgency_count = sum(1 for phrase in urgency_phrases if phrase in message_lower)
    if urgency_count > 0:
        spam_score += min(20, urgency_count * 5)
        detected_issues.append("Contains urgent language")
    
    # 3. Check for personal information requests
    personal_info_phrases = [
        'password', 'pin', 'otp', 'card number', 'credit card', 'debit card',
        'cvv', 'expiry date', 'bank account', 'login', 'username', 'verify',
        'confirm your', 'update your', 'validate', 'aadhaar', 'pan', 'kyc',
        'identification', 'id number', 'social security', 'date of birth'
    ]
    
    personal_info_count = sum(1 for phrase in personal_info_phrases if phrase in message_lower)
    if personal_info_count > 0:
        spam_score += min(25, personal_info_count * 5)
        detected_issues.append("Requests personal information")
    
    # 4. Check for suspicious URLs
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    urls = re.findall(url_pattern, message)
    
    suspicious_domains = [
        'bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
        'tiny.cc', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly', 'bit.do', 'cur.lv',
        'ity.im', 'q.gs', 'po.st', 'bc.vc', 'twitthis', 'u.to', 'j.mp', 'buzurl',
        'cutt.us', 'u.bb', 'yourls', 'x.co', 'prettylinkpro', 'scrnch', 'filoops',
        'vzturl', 'qr.net', '1url', 'tweez', 'v.gd', 'tr.im', 'link.zip'
    ]
    
    suspicious_url_count = 0
    for url in urls:
        domain = url.split('//')[-1].split('/')[0]
        if any(sd in domain for sd in suspicious_domains):
            suspicious_url_count += 1
    
    if suspicious_url_count > 0:
        spam_score += min(20, suspicious_url_count * 10)
        detected_issues.append("Contains suspicious URLs or shortened links")
    
    # 5. Check for excessive capitalization
    words = message.split()
    if len(words) > 3:  # Only check if message has more than 3 words
        caps_count = sum(1 for word in words if word.isupper() and len(word) > 1)
        caps_ratio = caps_count / len(words)
        
        if caps_ratio > 0.3:  # If more than 30% of words are ALL CAPS
            spam_score += min(15, int(caps_ratio * 30))
            detected_issues.append("Excessive use of UPPERCASE text")
    
    # 6. Check for excessive punctuation
    exclamation_count = message.count('!')
    if exclamation_count > 3:
        spam_score += min(10, exclamation_count * 2)
        detected_issues.append("Excessive exclamation marks")
    
    # 7. Check for Indian-specific scam patterns
    indian_scam_patterns = [
        # OTP fraud
        r'otp.*verification', r'share.*otp', r'send.*otp', r'otp.*expire',
        # KYC scams
        r'kyc.*update', r'kyc.*expire', r'kyc.*verify', r'aadhaar.*link',
        # Lottery/prize scams
        r'lottery.*win', r'prize.*claim', r'lucky.*draw', r'reward.*claim',
        # Job scams
        r'job.*offer', r'work.*home', r'earn.*daily', r'income.*guarantee',
        # Government scheme scams
        r'government.*scheme', r'pm.*scheme', r'subsidy.*claim', r'refund.*process'
    ]
    
    indian_scam_count = 0
    for pattern in indian_scam_patterns:
        if re.search(pattern, message_lower):
            indian_scam_count += 1
    
    if indian_scam_count > 0:
        spam_score += min(30, indian_scam_count * 10)
        detected_issues.append("Matches known Indian scam patterns")
    
    # 8. Check for phone numbers in the message
    phone_pattern = r'(?:\+\d{1,3}[-.\s]?)?$$?\d{3}$$?[-.\s]?\d{3}[-.\s]?\d{4}'
    phone_numbers = re.findall(phone_pattern, message)
    
    if phone_numbers:
        spam_score += min(15, len(phone_numbers) * 5)
        detected_issues.append("Contains phone numbers")
    
    # 9. Check for poor grammar and spelling
    # This is a simplified check - a real system would use NLP
    grammar_issues = 0
    
    # Check for common grammar mistakes
    grammar_patterns = [
        r'\byou is\b', r'\bhe are\b', r'\bshe are\b', r'\bthey is\b',
        r'\bi is\b', r'\bwe is\b', r'\byou was\b', r'\bthey was\b'
    ]
    
    for pattern in grammar_patterns:
        if re.search(pattern, message_lower):
            grammar_issues += 1
    
    # Check for repeated words
    repeated_word_pattern = r'\b(\w+)\s+\1\b'
    repeated_words = re.findall(repeated_word_pattern, message_lower)
    grammar_issues += len(repeated_words)
    
    if grammar_issues > 0:
        spam_score += min(15, grammar_issues * 5)
        detected_issues.append("Contains grammar or spelling errors")
    
    # Calculate final confidence and determine if it's spam
    confidence = min(98, spam_score)  # Cap at 98% to avoid absolute certainty
    is_spam = confidence > 60  # Consider it spam if confidence is over 60%
    
    # If it's not spam but has some suspicious elements, adjust confidence
    if not is_spam and detected_issues:
        confidence = max(5, confidence)  # Ensure minimum confidence of 5%
    elif not is_spam:
        confidence = max(95, 100 - confidence)  # High confidence for safe messages
    
    # Prepare detailed explanation
    if is_spam:
        if confidence > 90:
            explanation = "High confidence spam detection based on multiple indicators"
        elif confidence > 75:
            explanation = "Medium-high confidence spam detection"
        else:
            explanation = "Possible spam with some suspicious elements"
    else:
        if confidence > 90:
            explanation = "Message appears to be legitimate with high confidence"
        elif confidence > 75:
            explanation = "Message likely legitimate with some uncertainty"
        else:
            explanation = "Message doesn't contain strong spam indicators but has some suspicious elements"
    
    return {
        'is_spam': is_spam,
        'confidence': confidence,
        'details': {
            'detected_issues': detected_issues,
            'explanation': explanation
        }
    }

# API endpoint for analyzing websites
@app.route('/api/analyze-website', methods=['POST'])
def analyze_website():
    data = request.json
    url = data.get('websiteUrl', '')
    
    # Check if we've already analyzed this URL
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT is_phishing, confidence, phishing_indicators FROM phishing_sites WHERE url = ?", (url,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        is_phishing, confidence, phishing_indicators = result
        return jsonify({
            'status': 'success',
            'is_phishing': bool(is_phishing),
            'confidence': confidence,
            'result_type': 'danger' if is_phishing else 'safe',
            'details': json.loads(phishing_indicators) if phishing_indicators else {}
        })
    
    # If not analyzed before, use rule-based analysis
    analysis = analyze_website_url(url)
    
    # Store the analysis result
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO phishing_sites (url, is_phishing, confidence, phishing_indicators) VALUES (?, ?, ?, ?)",
        (url, analysis['is_phishing'], analysis['confidence'], json.dumps(analysis['details']))
    )
    conn.commit()
    conn.close()
    
    return jsonify({
        'status': 'success',
        'is_phishing': analysis['is_phishing'],
        'confidence': analysis['confidence'],
        'result_type': 'danger' if analysis['is_phishing'] else 'safe',
        'details': analysis['details']
    })

# Rule-based website URL analysis
def analyze_website_url(url):
    # Initialize scoring variables
    phishing_score = 0
    max_score = 100
    suspicious_factors = []
    
    # Parse the URL
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc.lower()
    
    # Extract domain information
    extracted = tldextract.extract(url)
    domain_name = extracted.domain
    tld = extracted.suffix
    
    # 1. Check for IP address instead of domain name
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.match(ip_pattern, domain):
        phishing_score += 25
        suspicious_factors.append("Uses IP address instead of domain name")
        
        # Check if it's a private IP
        try:
            ip = ipaddress.ip_address(domain)
            if ip.is_private:
                phishing_score += 10
                suspicious_factors.append("Uses private IP address")
        except:
            pass
    
    # 2. Check for suspicious TLDs
    suspicious_tlds = ['xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'work', 'date', 'racing', 'party']
    if tld in suspicious_tlds:
        phishing_score += 15
        suspicious_factors.append(f"Uses suspicious top-level domain (.{tld})")
    
    # 3. Check for excessive subdomains
    subdomain_count = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
    if subdomain_count > 3:
        phishing_score += 15
        suspicious_factors.append(f"Excessive number of subdomains ({subdomain_count})")
    
    # 4. Check for suspicious characters in domain
    if '@' in domain:
        phishing_score += 25
        suspicious_factors.append("Contains @ symbol in domain (URL redirection trick)")
    
    if '--' in domain:
        phishing_score += 10
        suspicious_factors.append("Contains double hyphens in domain")
    
    # 5. Check for excessive number of dots in domain
    dot_count = domain.count('.')
    if dot_count > 3:
        phishing_score += 10
        suspicious_factors.append(f"Excessive number of dots in domain ({dot_count})")
    
    # 6. Check for misspelled or lookalike domains of popular brands
    popular_brands = {
        'google': ['gooogle', 'g00gle', 'googel', 'gogle', 'googie'],
        'facebook': ['faceb00k', 'faceboook', 'facebok', 'facbook', 'faceb0ok'],
        'amazon': ['amaz0n', 'amazn', 'amazzon', 'amason', 'amozon'],
        'apple': ['appl', 'appie', 'appl3', 'applle', 'aple'],
        'microsoft': ['micr0soft', 'microsooft', 'microsft', 'micosoft', 'microsof'],
        'paypal': ['payp', 'paypai', 'paypol', 'paypa1', 'paypall'],
        'netflix': ['netfllx', 'netfl1x', 'netflex', 'netfiix', 'netflx'],
        'instagram': ['1nstagram', 'lnstagram', 'instagramm', 'instagam', 'instagrarn'],
        'whatsapp': ['whatsap', 'whatsaap', 'whatsapp', 'whatsappp', 'whatsop'],
        'gmail': ['gma1l', 'gmaill', 'gmial', 'gmall', 'gmai1'],
        'yahoo': ['yah00', 'yaho0', 'yahho', 'yahooo', 'yah0o'],
        'hotmail': ['h0tmail', 'hotmall', 'hotmaill', 'hotmai1', 'hotmial'],
        'outlook': ['0utlook', 'outl00k', 'outlok', 'outllook', 'outlok'],
        'linkedin': ['l1nkedin', 'linkedln', 'linkediin', 'linkedn', 'llnkedin'],
        'twitter': ['tw1tter', 'twltter', 'twiter', 'twitterr', 'twwitter'],
        'bank': ['banck', 'bancк', 'bаnk', 'bаnс', 'bаnk'],
        'secure': ['secur', 'securre', 'secuure', 'securee', 'secur3'],
        'account': ['acc0unt', 'acct', 'acoun', 'accoount', 'acount']
    }
    
    for brand, variations in popular_brands.items():
        # Check if domain contains brand name
        if brand in domain_name:
            continue  # Skip if it's the actual brand
            
        # Check for lookalike domains
        for variation in variations:
            if variation in domain_name:
                phishing_score += 25
                suspicious_factors.append(f"Domain mimics {brand} with slight variation")
                break
    
    # 7. Check for suspicious URL path
    path = parsed_url.path.lower()
    
    suspicious_path_keywords = [
        'login', 'signin', 'verify', 'secure', 'account', 'password', 'banking',
        'update', 'confirm', 'authenticate', 'wallet', 'authorize', 'validation'
    ]
    
    path_keywords_found = [keyword for keyword in suspicious_path_keywords if keyword in path]
    if path_keywords_found:
        phishing_score += min(20, len(path_keywords_found) * 5)
        suspicious_factors.append(f"URL path contains suspicious keywords: {', '.join(path_keywords_found)}")
    
    # 8. Check for excessive URL parameters
    params = parsed_url.query
    param_count = len(params.split('&')) if params else 0
    if param_count > 5:
        phishing_score += 10
        suspicious_factors.append(f"Excessive number of URL parameters ({param_count})")
    
    # 9. Check for URL redirects in parameters
    redirect_params = ['url', 'redirect', 'link', 'goto', 'return', 'returnurl', 'return_url', 'next']
    for param in redirect_params:
        if f"{param}=" in params:
            phishing_score += 15
            suspicious_factors.append("Contains URL redirection in parameters")
            break
    
    # 10. Check for data URIs
    if url.startswith('data:'):
        phishing_score += 25
        suspicious_factors.append("Uses data URI scheme (often used in phishing)")
    
    # Calculate final confidence and determine if it's phishing
    confidence = min(98, phishing_score)  # Cap at 98% to avoid absolute certainty
    is_phishing = confidence > 60  # Consider it phishing if confidence is over 60%
    
    # If it's not phishing but has some suspicious elements, adjust confidence
    if not is_phishing and suspicious_factors:
        confidence = max(5, confidence)  # Ensure minimum confidence of 5%
    elif not is_phishing:
        confidence = max(95, 100 - confidence)  # High confidence for safe sites
    
    # Prepare detailed explanation
    if is_phishing:
        if confidence > 90:
            explanation = "High confidence phishing detection based on multiple indicators"
        elif confidence > 75:
            explanation = "Medium-high confidence phishing detection"
        else:
            explanation = "Possible phishing with some suspicious elements"
    else:
        if confidence > 90:
            explanation = "Website appears to be legitimate with high confidence"
        elif confidence > 75:
            explanation = "Website likely legitimate with some uncertainty"
        else:
            explanation = "Website doesn't contain strong phishing indicators but has some suspicious elements"
    
    return {
        'is_phishing': is_phishing,
        'confidence': confidence,
        'details': {
            'suspicious_factors': suspicious_factors,
            'explanation': explanation
        }
    }

# API endpoint for getting dashboard stats
@app.route('/api/dashboard-stats', methods=['GET'])
def dashboard_stats():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Get total threats
    cursor.execute("SELECT COUNT(*) FROM spam_numbers")
    total_spam_numbers = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM message_analysis WHERE is_spam = 1")
    total_spam_messages = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM phishing_sites WHERE is_phishing = 1")
    total_phishing_sites = cursor.fetchone()[0]
    
    total_threats = total_spam_numbers + total_spam_messages + total_phishing_sites
    
    # Get blocked attempts (for demo, we'll use a percentage of total threats)
    blocked_attempts = int(total_threats * 0.8)
    
    # Get active threats (for demo, we'll use a percentage of total threats)
    active_threats = int(total_threats * 0.02)
    
    # Calculate security score
    security_score = 100 - min(100, (active_threats / max(1, total_threats)) * 100)
    
    conn.close()
    
    return jsonify({
        'total_threats': total_threats,
        'blocked_attempts': blocked_attempts,
        'active_threats': active_threats,
        'security_score': round(security_score)
    })

# API endpoint for getting recent activity
@app.route('/api/recent-activity', methods=['GET'])
def recent_activity():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row  # This enables column access by name
    cursor = conn.cursor()
    
    # Get recent spam reports
    cursor.execute("""
    SELECT 'spam_number' as type, phone_number as content, report_time, spam_type as details
    FROM spam_reports
    ORDER BY report_time DESC
    LIMIT 2
    """)
    spam_reports = [dict(row) for row in cursor.fetchall()]
    
    # Get recent message analysis
    cursor.execute("""
    SELECT 'message' as type, substr(message_hash, 1, 10) as content, analysis_time as report_time, 
           CASE WHEN is_spam THEN 'Spam Message Detected' ELSE 'Safe Message' END as details
    FROM message_analysis
    ORDER BY analysis_time DESC
    LIMIT 2
    """)
    message_analysis = [dict(row) for row in cursor.fetchall()]
    
    # Get recent phishing site analysis
    cursor.execute("""
    SELECT 'website' as type, url as content, analysis_time as report_time,
           CASE WHEN is_phishing THEN 'Phishing Attempt Blocked' ELSE 'Safe Website' END as details
    FROM phishing_sites
    ORDER BY analysis_time DESC
    LIMIT 2
    """)
    phishing_analysis = [dict(row) for row in cursor.fetchall()]
    
    # Combine and sort by time
    all_activity = spam_reports + message_analysis + phishing_analysis
    all_activity.sort(key=lambda x: x['report_time'], reverse=True)
    
    # Take the most recent 4
    recent_activity = all_activity[:4]
    
    # Format the activity for display
    formatted_activity = []
    for activity in recent_activity:
        activity_type = activity['type']
        content = activity['content']
        details = activity['details']
        
        if activity_type == 'spam_number':
            icon_class = 'phone-slash'
            title = f"Spam Call Blocked"
            description = f"A spam call from number {content} was blocked"
            activity_class = 'warning'
        elif activity_type == 'message':
            if 'Spam' in details:
                icon_class = 'virus'
                title = "Spam Message Detected"
                description = "A spam message containing suspicious links was detected and quarantined"
                activity_class = 'danger'
            else:
                icon_class = 'shield-alt'
                title = "Safe Message"
                description = "Message analyzed and found to be safe"
                activity_class = 'success'
        elif activity_type == 'website':
            if 'Phishing' in details:
                icon_class = 'exclamation-circle'
                title = "Phishing Attempt Blocked"
                description = f"A phishing attempt from domain \"{content}\" was blocked"
                activity_class = 'warning'
            else:
                icon_class = 'shield-alt'
                title = "Safe Website"
                description = f"Website {content} analyzed and found to be safe"
                activity_class = 'success'
        
        # Calculate time ago
        report_time = datetime.strptime(activity['report_time'], '%Y-%m-%d %H:%M:%S')
        now = datetime.now()
        diff = now - report_time
        
        if diff.days > 0:
            time_ago = f"{diff.days} days ago"
        elif diff.seconds // 3600 > 0:
            time_ago = f"{diff.seconds // 3600} hours ago"
        elif diff.seconds // 60 > 0:
            time_ago = f"{diff.seconds // 60} minutes ago"
        else:
            time_ago = "Just now"
        
        formatted_activity.append({
            'icon_class': icon_class,
            'title': title,
            'description': description,
            'time_ago': time_ago,
            'activity_class': activity_class
        })
    
    conn.close()
    
    return jsonify(formatted_activity)

# Add a route to report spam numbers
@app.route('/api/report-spam', methods=['POST'])
def report_spam():
    data = request.json
    phone_number = data.get('phoneNumber', '')
    report_details = data.get('details', '')
    report_source = data.get('source', 'user_report')
    
    # Clean the phone number
    phone_number = re.sub(r'\s+|-|$$|$$', '', phone_number)
    
    # Get reporter IP (in a real app, you'd want to handle this more securely)
    reporter_ip = request.remote_addr
    
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Add report to spam_reports table
    cursor.execute(
        "INSERT INTO spam_reports (phone_number, report_source, report_details, reporter_ip) VALUES (?, ?, ?, ?)",
        (phone_number, report_source, report_details, reporter_ip)
    )
    
    # Check if number already exists in spam_numbers
    cursor.execute("SELECT report_count, spam_score FROM spam_numbers WHERE phone_number = ?", (phone_number,))
    result = cursor.fetchone()
    
    if result:
        # Update existing record
        report_count, current_score = result
        new_count = report_count + 1
        # Adjust score slightly upward with each new report
        new_score = min(0.99, current_score + (1 - current_score) * 0.1)
        
        cursor.execute(
            "UPDATE spam_numbers SET report_count = ?, spam_score = ?, last_reported = CURRENT_TIMESTAMP WHERE phone_number = ?",
            (new_count, new_score, phone_number)
        )
    else:
        # Create new record
        hash_value = hashlib.md5(phone_number.encode()).hexdigest()
        cursor.execute(
            "INSERT INTO spam_numbers (phone_number, spam_score, hash, spam_type) VALUES (?, ?, ?, ?)",
            (phone_number, 0.85, hash_value, report_details)
        )
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'status': 'success',
        'message': 'Spam report submitted successfully'
    })

# Add JavaScript to connect the frontend to the backend
@app.route('/static/js/backend-connector.js')
def backend_connector():
    js_code = """
    // Backend connector for Threat Detection Dashboard
    document.addEventListener('DOMContentLoaded', function() {
        // Load dashboard stats
        fetch('/api/dashboard-stats')
            .then(response => response.json())
            .then(data => {
                document.querySelector('.stat-card:nth-child(1) .stat-value').textContent = data.total_threats.toLocaleString();
                document.querySelector('.stat-card:nth-child(2) .stat-value').textContent = data.blocked_attempts.toLocaleString();
                document.querySelector('.stat-card:nth-child(3) .stat-value').textContent = data.active_threats.toLocaleString();
                document.querySelector('.stat-card:nth-child(4) .stat-value').textContent = data.security_score + '%';
            })
            .catch(error => console.error('Error loading dashboard stats:', error));
        
        // Load recent activity
        fetch('/api/recent-activity')
            .then(response => response.json())
            .then(data => {
                const activityList = document.querySelector('.activity-list');
                activityList.innerHTML = '';
                
                data.forEach(activity => {
                    const activityItem = document.createElement('div');
                    activityItem.className = 'activity-item';
                    activityItem.innerHTML = `
                        <div class="activity-icon ${activity.activity_class}">
                            <i class="fas fa-${activity.icon_class}"></i>
                        </div>
                        <div class="activity-info">
                            <h4>${activity.title}</h4>
                            <p>${activity.description}</p>
                            <span class="activity-time"><i class="fas fa-clock"></i> ${activity.time_ago}</span>
                        </div>
                    `;
                    activityList.appendChild(activityItem);
                });
            })
            .catch(error => console.error('Error loading recent activity:', error));
        
        // Message form submission
        const messageForm = document.getElementById('messageForm');
        if (messageForm) {
            messageForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const messageText = document.getElementById('messageText').value;
                const safeResult = document.getElementById('messageSafeResult');
                const spamResult = document.getElementById('messageSpamResult');
                const resultsContainer = document.getElementById('messageResults');
                
                // Hide all results
                safeResult.classList.add('hidden');
                spamResult.classList.add('hidden');
                
                // Show loading animation
                resultsContainer.classList.add('show-results');
                
                // Call backend API
                fetch('/api/analyze-message', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ message: messageText }),
                })
                .then(response => response.json())
                .then(data => {
                    // Update timestamp
                    document.getElementById('messageAnalysisTime').textContent = 'Just now';
                    
                    // Show appropriate result
                    if (data.is_spam) {
                        safeResult.classList.add('hidden');
                        spamResult.classList.remove('hidden');
                        
                        // Update detected issues if available
                        if (data.details && data.details.detected_issues) {
                            const issuesList = spamResult.querySelector('.threat-details ul');
                            issuesList.innerHTML = '';
                            data.details.detected_issues.forEach(issue => {
                                const li = document.createElement('li');
                                li.textContent = issue;
                                issuesList.appendChild(li);
                            });
                        }
                        
                        // Update confidence value
                        spamResult.querySelector('.confidence-value').textContent = data.confidence + '%';
                        
                        // Animate confidence meter
                        setTimeout(() => {
                            document.getElementById('messageSpamConfidence').style.width = data.confidence + '%';
                        }, 100);
                    } else {
                        spamResult.classList.add('hidden');
                        safeResult.classList.remove('hidden');
                        
                        // Update confidence value
                        safeResult.querySelector('.confidence-value').textContent = data.confidence + '%';
                        
                        // Animate confidence meter
                        setTimeout(() => {
                            document.getElementById('messageSafeConfidence').style.width = data.confidence + '%';
                        }, 100);
                    }
                    
                    // Scroll to results
                    resultsContainer.scrollIntoView({ behavior: 'smooth' });
                })
                .catch(error => {
                    console.error('Error analyzing message:', error);
                    alert('Error analyzing message. Please try again.');
                });
            });
        }
        
        // Mobile form submission
        const mobileForm = document.getElementById('mobileForm');
        if (mobileForm) {
            mobileForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const phoneNumber = document.getElementById('phoneNumber').value;
                const safeResult = document.getElementById('mobileSafeResult');
                const spamResult = document.getElementById('mobileSpamResult');
                const invalidResult = document.getElementById('mobileInvalidResult');
                const resultsContainer = document.getElementById('mobileResults');
                
                // Hide all results
                safeResult.classList.add('hidden');
                spamResult.classList.add('hidden');
                invalidResult.classList.add('hidden');
                
                // Show loading animation
                resultsContainer.classList.add('show-results');
                
                // Call backend API
                fetch('/api/check-number', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ phoneNumber: phoneNumber }),
                })
                .then(response => response.json())
                .then(data => {
                    // Update timestamp
                    document.getElementById('mobileAnalysisTime').textContent = 'Just now';
                    
                    if (data.status === 'error' || data.result_type === 'invalid') {
                        invalidResult.classList.remove('hidden');
                    } else if (data.is_spam) {
                        spamResult.classList.remove('hidden');
                        
                        // Update spam information if available
                        if (data.details) {
                            const infoList = spamResult.querySelector('.threat-details ul');
                            infoList.innerHTML = '';
                            
                            if (data.details.reported_count) {
                                const li = document.createElement('li');
                                li.textContent = `Reported by ${data.details.reported_count} users`;
                                infoList.appendChild(li);
                            }
                            
                            if (data.details.spam_type) {
                                const li = document.createElement('li');
                                li.textContent = `Known for ${data.details.spam_type}`;
                                infoList.appendChild(li);
                            }
                            
                            if (data.details.first_reported) {
                                const li = document.createElement('li');
                                li.textContent = `First reported: ${data.details.first_reported}`;
                                infoList.appendChild(li);
                            }
                            
                            if (data.details.analysis) {
                                const li = document.createElement('li');
                                li.textContent = data.details.analysis;
                                infoList.appendChild(li);
                            }
                        }
                        
                        // Update confidence value
                        spamResult.querySelector('.confidence-value').textContent = data.confidence + '%';
                        
                        // Animate confidence meter
                        setTimeout(() => {
                            document.getElementById('mobileSpamConfidence').style.width = data.confidence + '%';
                        }, 100);
                    } else {
                        safeResult.classList.remove('hidden');
                        
                        // Update confidence value
                        safeResult.querySelector('.confidence-value').textContent = data.confidence + '%';
                        
                        // Animate confidence meter
                        setTimeout(() => {
                            document.getElementById('mobileSafeConfidence').style.width = data.confidence + '%';
                        }, 100);
                    }
                    
                    // Scroll to results
                    resultsContainer.scrollIntoView({ behavior: 'smooth' });
                })
                .catch(error => {
                    console.error('Error checking phone number:', error);
                    alert('Error checking phone number. Please try again.');
                });
            });
        }
        
        // Phishing form submission
        const phishingForm = document.getElementById('phishingForm');
        if (phishingForm) {
            phishingForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const websiteUrl = document.getElementById('websiteUrl').value;
                const safeResult = document.getElementById('phishingSafeResult');
                const dangerResult = document.getElementById('phishingDangerResult');
                const scanProgress = document.getElementById('scanProgress');
                const resultsContainer = document.getElementById('phishingResults');
                
                // Hide results, show progress
                safeResult.classList.add('hidden');
                dangerResult.classList.add('hidden');
                scanProgress.classList.remove('hidden');
                resultsContainer.classList.add('show-results');
                
                // Reset progress
                const progressFill = document.getElementById('progressFill');
                const progressStep = document.getElementById('progressStep');
                const progressPercentage = document.getElementById('progressPercentage');
                progressFill.style.width = '0%';
                
                // Animate progress bar
                let progress = 0;
                const progressInterval = setInterval(() => {
                    progress += 5;
                    progressFill.style.width = `${progress}%`;
                    progressPercentage.textContent = `${progress}%`;
                    
                    if (progress === 25) {
                        progressStep.textContent = 'Checking SSL certificate...';
                    } else if (progress === 50) {
                        progressStep.textContent = 'Analyzing content...';
                    } else if (progress === 75) {
                        progressStep.textContent = 'Checking reputation databases...';
                    }
                    
                    if (progress >= 100) {
                        clearInterval(progressInterval);
                        
                        // Call backend API
                        fetch('/api/analyze-website', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({ websiteUrl: websiteUrl }),
                        })
                        .then(response => response.json())
                        .then(data => {
                            // Update timestamp
                            document.getElementById('phishingAnalysisTime').textContent = 'Just now';
                            
                            // Hide progress, show results
                            scanProgress.classList.add('hidden');
                            
                            if (data.is_phishing) {
                                dangerResult.classList.remove('hidden');
                                
                                // Update detected issues if available
                                if (data.details && data.details.suspicious_factors) {
                                    const issuesList = dangerResult.querySelector('.threat-details ul');
                                    issuesList.innerHTML = '';
                                    data.details.suspicious_factors.forEach(factor => {
                                        const li = document.createElement('li');
                                        li.textContent = factor;
                                        issuesList.appendChild(li);
                                    });
                                }
                                
                                // Update confidence value
                                dangerResult.querySelector('.confidence-value').textContent = data.confidence + '%';
                                
                                // Animate confidence meter
                                setTimeout(() => {
                                    document.getElementById('phishingDangerConfidence').style.width = data.confidence + '%';
                                }, 100);
                            } else {
                                safeResult.classList.remove('hidden');
                                
                                // Update confidence value
                                safeResult.querySelector('.confidence-value').textContent = data.confidence + '%';
                                
                                // Animate confidence meter
                                setTimeout(() => {
                                    document.getElementById('phishingSafeConfidence').style.width = data.confidence + '%';
                                }, 100);
                            }
                        })
                        .catch(error => {
                            console.error('Error analyzing website:', error);
                            alert('Error analyzing website. Please try again.');
                            scanProgress.classList.add('hidden');
                        });
                    }
                }, 100);
            });
        }
    });
    """
    return js_code, 200, {'Content-Type': 'application/javascript'}

# Run the app
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)