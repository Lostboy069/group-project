import re
import logging
import requests
import os
import base64
import time
from typing import Dict, Any
from transformers import pipeline

logging.basicConfig(level=logging.INFO)

class ThreatDetector:
    def __init__(self):
        self.model_loaded = False
        self.classifier = None
        self.vt_api_key = os.getenv("VT_API_KEY")
        self._load_model()

    def _load_model(self):
        try:
            logging.info("Loading phishing detection model...")
            
            # Authenticate with Hugging Face if token is available
            hf_token = os.getenv("HF_TOKEN")
            if hf_token:
                try:
                    from huggingface_hub import login
                    login(token=hf_token, add_to_git_credential=False)
                    logging.info("Authenticated with Hugging Face.")
                except ImportError:
                    logging.warning("huggingface_hub not installed. Install with: pip install huggingface_hub")
                except Exception as auth_err:
                    logging.warning(f"Auth failed: {auth_err}")
            
            cache_dir = os.path.join(os.path.dirname(__file__), "hf_cache")
            os.makedirs(cache_dir, exist_ok=True)
            
            self.classifier = pipeline(
                "text-classification",
                model="mrm8488/bert-base-finetuned-phishing-detection",
                truncation=True,
                max_length=512,
                device=-1,
                cache_dir=cache_dir
            )
            self.model_loaded = True
            logging.info("Model loaded successfully.")
        except Exception as e:
            logging.warning(f"Model load failed: {e}. Falling back to rule-based detection.")
            self.model_loaded = False

    def analyze_message(self, text: str) -> Dict[str, Any]:
        if not text.strip():
            return {"risk": "LOW", "score": 0, "prediction": "EMPTY", "details": "No input provided."}

        ai_score = 0
        ai_label = "SAFE"
        if self.model_loaded:
            try:
                result = self.classifier(text)[0]
                ai_label = result["label"]
                ai_score = int(result["score"] * 100)
            except Exception as e:
                logging.warning(f"AI inference failed: {e}")

        rule_score = self._rule_based_score_enhanced(text)
        final_score = max(ai_score, rule_score)
        risk = self._calculate_risk(final_score)

        return {
            "risk": risk,
            "score": final_score,
            "prediction": ai_label if self.model_loaded else "RULE_BASED",
            "details": self._generate_explanation_enhanced(text, ai_score, rule_score, final_score)
        }

    def analyze_url(self, url: str) -> Dict[str, Any]:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        details = []
        score = 0
        
        if self.vt_api_key:
            vt_result = self._scan_url_virustotal(url)
            if vt_result:
                return vt_result
        
        if self._has_suspicious_tld(url): score += 20; details.append("Suspicious domain extension")
        if self._contains_ip(url): score += 25; details.append("Direct IP address detected")
        if self._is_shortened(url): score += 15; details.append("URL shortener used")
        if self._has_excessive_params(url): score += 10; details.append("Excessive tracking parameters")
        if self._uses_http_mismatch(url): score += 30; details.append("HTTP used on sensitive URL")
        if self._has_phishing_keywords(url): score += 20; details.append("Suspicious keywords in URL")
        if self._is_obfuscated_url(url): score += 35; details.append("Obfuscated URL pattern")
        if self._has_malicious_redirect(url): score += 25; details.append("Suspicious redirect chain")
        if self._has_encoded_payload(url): score += 30; details.append("Encoded payload detected")

        score = min(score, 100)
        risk = self._calculate_risk(score)
        
        return {
            "risk": risk,
            "score": score,
            "prediction": "MALICIOUS" if risk == "HIGH" else "SUSPICIOUS" if risk == "MEDIUM" else "CLEAN",
            "details": " | ".join(details) if details else "No obvious threats detected."
        }

    def _scan_url_virustotal(self, url: str) -> Dict[str, Any]:
        if not self.vt_api_key:
            return None
            
        try:
            headers = {"x-apikey": self.vt_api_key}
            submit_url = "https://www.virustotal.com/api/v3/urls"
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
            res = requests.get(analysis_url, headers=headers, timeout=15)
            
            if res.status_code == 404:
                data = {"url": url}
                submit_res = requests.post(submit_url, headers=headers, data=data, timeout=15)
                if submit_res.status_code != 200:
                    return None
                analysis_id = submit_res.json()["data"]["id"]
                time.sleep(3)
                res = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=15)
            
            if res.status_code == 200:
                stats = res.json()["data"]["attributes"]["stats"]
                mal = stats.get("malicious", 0)
                sus = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                
                if mal > 0:
                    score = min(90 + mal * 2, 100)
                    risk = "HIGH"
                    prediction = "MALICIOUS"
                    details = f"VT: {mal} malicious, {sus} suspicious, {harmless} clean"
                elif sus > 2:
                    score = 60 + sus * 5
                    risk = "MEDIUM"
                    prediction = "SUSPICIOUS"
                    details = f"VT: {mal} malicious, {sus} suspicious, {harmless} clean"
                else:
                    score = 10
                    risk = "LOW"
                    prediction = "CLEAN"
                    details = f"VT: {harmless} vendors report clean"
                
                return {
                    "risk": risk,
                    "score": score,
                    "prediction": prediction,
                    "details": details
                }
        except Exception as e:
            logging.warning(f"VirusTotal URL scan failed: {e}")
        
        return None

    def _rule_based_score_enhanced(self, text: str) -> int:
        text_lower = text.lower()
        score = 0

        urgency = r'\b(urgent|immediately|asap|within \d+ minutes?|expire|deadline|last chance|act now|confirm now|final notice)\b'
        threat = r'\b(suspended|locked|blocked|terminated|forfeiture|blacklist|legal action|law enforcement|permanent loss|irreversible)\b'
        financial = r'\b(\$\d+|USD|EUR|GBP|transfer|payment|refund|transaction|account balance|funds|money|invoice|billing)\b'
        
        if re.search(urgency, text_lower) and re.search(threat, text_lower):
            score += 35
        if re.search(urgency, text_lower) and re.search(financial, text_lower):
            score += 30
        
        authority = [
            r'\b(security (dept|department|team)|technical support|customer service|billing department|account services|fraud prevention|compliance team|verification center)\b',
            r'\b(verify your (identity|credentials|account|information)|confirm your (details|identity|account)|update your (profile|settings|password))\b',
            r'\b(unauthorized (access|activity|login|transaction)|suspicious (activity|login|behavior|sign-in)|violation of terms|policy breach)\b',
            r'\b(we have detected|our system flagged|unusual activity detected|new device login|location change detected)\b'
        ]
        for pattern in authority:
            if re.search(pattern, text_lower):
                score += 25
                break
        
        if re.search(r'hxxp[s]?://', text_lower) or re.search(r'\[\.\]|\[dot\]|\(dot\)', text_lower):
            score += 40
        
        if re.search(r'[a-zA-Z][\|\-\_\.\@][a-zA-Z]', text_lower) and re.search(r'https?://|http://|www\.', text_lower):
            score += 30
        
        if re.search(r'https?://[^\s]+', text_lower):
            score += 15
            if re.search(r'(login|verify|secure|update|account|bank|paypal|amazon|microsoft|apple|google|netflix|spotify)[\-_\.\w]*\.?[a-z]{2,6}/', text_lower):
                score += 20
        
        if re.search(r'\b(bit\.ly|tinyurl\.com|t\.co|short\.link|cut\.ly|is\.gd|ow\.ly|goo\.gl)\b', text_lower):
            score += 25
        
        phishing_keywords = [
            r'\b(verify|confirm|update|validate|authenticate|authorize|reactivate|restore|renew)\b',
            r'\b(password|pin|ssn|social security|credit card|bank details|account number|cvv|security code)\b',
            r'\b(click here|click the link|visit this page|follow this link|tap here|press here|open this)\b',
            r'\b(won|prize|lottery|inheritance|unclaimed funds|bonus|reward|gift card|free)\b',
            r'\b(failed login|unusual activity|suspicious sign-in|new device detected|location change|password reset required)\b',
            r'\b(attachment|download|open attached|see attached|file attached)\b.*\.(exe|scr|bat|cmd|js|vbs|hta|pif)\b'
        ]
        for kw in phishing_keywords:
            if re.search(kw, text_lower):
                score += 15
                break
        
        if re.search(r'[aA][@4]ccount|[cC][1|]lick|[pP][@]ssw[o0]rd|[vV]3rify|[sS][1|]gn|[iI][1|]dent[i1]ty|[wW][1|]ll|[pP][1|]ease|[rR]equest|[uU]rgent', text_lower):
            score += 30
        
        if len(text.split()) < 15 and re.search(r'https?://', text_lower):
            score += 20
        
        if text.count('!') >= 3 or (len(re.findall(r'\b[A-Z]{4,}\b', text)) >= 3 and len(text) < 600):
            score += 15
        
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text_lower):
            score += 35
        
        if re.search(r'(thank you for your (business|patience|understanding)|we appreciate your (cooperation|prompt attention))', text_lower) and re.search(urgency, text_lower):
            score += 20
        
        if re.search(r'\b(do not (reply|ignore|delay|hesitate)|ignore this message at your own risk)\b', text_lower):
            score += 15
        
        if re.search(r'\b(official|verified|secure|protected|encrypted|ssl|https required)\b', text_lower) and re.search(r'http://', text_lower):
            score += 25
        
        return min(score, 100)

    def _generate_explanation_enhanced(self, text, ai_score, rule_score, final_score):
        explanations = []
        text_lower = text.lower()
        
        if final_score >= 80:
            explanations.append("AI highly confident: Phishing patterns detected")
        elif rule_score > ai_score and rule_score >= 60:
            explanations.append("Rule engine flagged multiple phishing indicators")
        
        if re.search(r'hxxp|\\\[\.\\\]|\(dot\)', text_lower):
            explanations.append("Obfuscated URL detected")
        if re.search(r'[a-zA-Z][\|\-\_\.\@][a-zA-Z].*https?://', text_lower):
            explanations.append("Character substitution in link")
        if re.search(r'\b(urgent|immediately).*\b(suspended|locked|forfeiture|irreversible)\b', text_lower):
            explanations.append("Urgency + account threat combo")
        if re.search(r'\b(security dept|technical support|fraud prevention).*verify', text_lower):
            explanations.append("Fake authority impersonation")
        if re.search(r'[aA][@4]ccount|[cC][1|]ick|[pP][@]ssw', text_lower):
            explanations.append("Leetspeak/obfuscation detected")
        if re.search(r'\b(attachment|download).*\.(exe|scr|bat|cmd|js)\b', text_lower):
            explanations.append("Suspicious attachment detected")
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text_lower):
            explanations.append("Direct IP address in URL")
        
        if not explanations:
            if final_score >= 70:
                explanations.append("High-risk patterns detected in language structure")
            elif final_score >= 40:
                explanations.append("Moderate risk indicators present")
            else:
                explanations.append("Low threat indicators detected")
        
        return " | ".join(explanations)

    def _has_suspicious_tld(self, url): 
        return bool(re.search(r'\.(xyz|top|club|work|buzz|info|tk|ml|ga|cf|gq|click|link|site|online|space|tech|loan|win|bid|date|review)\b', url, re.I))
    
    def _contains_ip(self, url): 
        return bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url))
    
    def _is_shortened(self, url): 
        return any(s in url.lower() for s in ['bit.ly', 'tinyurl', 't.co', 'short.link', 'cut.ly', 'is.gd', 'ow.ly', 'goo.gl'])
    
    def _has_excessive_params(self, url): 
        return url.count('?') > 1 or url.count('&') > 4
    
    def _uses_http_mismatch(self, url): 
        return url.lower().startswith('http://') and re.search(r'(login|account|bank|secure|verify|payment|billing|invoice)', url.lower())
    
    def _has_phishing_keywords(self, url): 
        return bool(re.search(r'(login|verify|secure|update|account|support|bank|paypal|amazon|apple|microsoft|google|netflix|spotify|dropbox|icloud)\b', url.split('://')[-1].split('/')[0], re.I))
    
    def _is_obfuscated_url(self, url):
        url_lower = url.lower()
        if re.search(r'hxxp[s]?://', url_lower):
            return True
        if re.search(r'\[\.\]|\[dot\]|\(dot\)', url_lower):
            return True
        if re.search(r'[a-z][\|\-\_\.\@01][a-z]+\.[a-z]{2,6}', url_lower):
            return True
        return False
    
    def _has_malicious_redirect(self, url):
        return bool(re.search(r'(redirect|redir|go\.php|out\.php|click\.php|track\.php|ref=|utm_)', url.lower()))
    
    def _has_encoded_payload(self, url):
        return bool(re.search(r'(%[0-9a-fA-F]{2}){3,}|base64|javascript:|data:|vbscript:|about:', url))

    def _calculate_risk(self, score):
        if score >= 70: return "HIGH"
        elif score >= 40: return "MEDIUM"
        return "LOW"