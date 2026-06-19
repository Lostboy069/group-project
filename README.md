# 🛡️ AI Cyber Shield

> **Advanced Phishing Detection System** — Hybrid AI + Rule-Based Threat Analysis

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3-black?logo=flask)](https://flask.palletsprojects.com)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-API-green?logo=virustotal)](https://virustotal.com)
[![Hugging Face](https://img.shields.io/badge/Hugging_Face-BERT-yellow?logo=huggingface)](https://huggingface.co)
[![License](https://img.shields.io/badge/License-MIT-orange)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production_Ready-brightgreen)](#)

---

## 🔍 Overview

**AI Cyber Shield** is a comprehensive phishing detection platform that combines:
- 🤖 **BERT-based AI model** for deep learning text classification
- 📏 **12+ rule-based detectors** for instant pattern recognition
- 🔗 **VirusTotal API integration** for real-time link & file intelligence
- 📄 **In-memory PDF report generation** with threat visualization

Designed for cybersecurity education, threat awareness, and rapid phishing analysis.

---

## ✨ Features

### 🔗 Link Scanner
- Real-time VirusTotal API lookup
- Suspicious TLD detection (`.xyz`, `.tk`, `.top`, etc.)
- Obfuscated URL detection (`hxxp://`, `[.]` notation)
- URL shortener analysis (`bit.ly`, `tinyurl`, etc.)
- Direct IP address & redirect chain detection

### 📁 File Analyzer
- SHA-256 hash generation for uploaded files
- VirusTotal hash lookup for known malware
- Safe, in-memory processing (no disk storage)

### 💬 Message AI
- **Hybrid Detection**: BERT model + enhanced rule engine
- Detects: urgency language, authority impersonation, financial pressure
- Character substitution obfuscation (`acc0unt`, `cl|ck`, `p@ssw0rd`)
- Explainable results with detailed threat breakdowns

### 📄 Professional Reports
- Auto-generated PDF reports with threat visualization
- Color-coded risk levels (🔴 HIGH / 🟡 MEDIUM / 🟢 LOW)
- Pie chart threat distribution
- Timestamped, branded output for documentation

---

## 🚀 Live Demo

| Component | URL |
|-----------|-----|
| **Frontend** | [https://ai-cyber-shield.netlify.app](https://ai-cyber-shield.netlify.app) |
| **Backend API** | [https://ai-cyber-shield-production-619e.up.railway.app](https://ai-cyber-shield-production-619e.up.railway.app) |
| **Health Check** | [`/health`](https://ai-cyber-shield-production-619e.up.railway.app/health) |

---

## 🛠️ Tech Stack

### Backend
