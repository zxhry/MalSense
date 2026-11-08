"""
Sprint 5 - Step 1: Check the Gemini API key and generate one test quiz.
Usage: python tests/test_gemini.py
"""
import os, sys, json
import requests
from dotenv import load_dotenv
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
load_dotenv()

key = os.getenv("GEMINI_API_KEY")
model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
print("=== GEMINI API TEST ===")
if not key:
    sys.exit("GEMINI_API_KEY is missing in .env")

# 1. Which models can this key use?
r = requests.get("https://generativelanguage.googleapis.com/v1beta/models",
                 headers={"x-goog-api-key": key}, params={"pageSize": 200}, timeout=20)
if r.status_code != 200:
    sys.exit(f"Key check FAILED: HTTP {r.status_code} {r.text[:200]}")
flash = sorted(m["name"].split("/")[-1] for m in r.json().get("models", [])
               if "generateContent" in m.get("supportedGenerationMethods", []) and "flash" in m["name"])
print(f"Key OK. Flash models available to you: {', '.join(flash)}")
print(f"Model set in .env (GEMINI_MODEL): {model}  ->  {'available' if model in flash else 'NOT in the list - pick one above'}")

# 2. Generate a quiz for the sample app (model only, no VirusTotal needed)
from malsense_scanner import scan_apk
from quiz import new_quiz
r = scan_apk(os.path.join(os.path.dirname(__file__), "..", "samples", "a2dp.Vol_137.apk"))
details = {k: r[k] for k in ("app_name", "verdict", "dangerous_permissions", "explanation")} | {"risk": "LOW"}
_, quiz = new_quiz(details, r["sha256"])
print(f"\nQuiz source: {quiz['source']}")
if quiz["note"]:
    print(f"Why the AI was not used: {quiz['note']}")
for i, q in enumerate(quiz["questions"], 1):
    print(f"\nQ{i} [{q['category']}] {q['question']}")
    for j, o in enumerate(q["options"]):
        print(f"   {'ABCD'[j]}. {o}{'   <-- correct' if j == q['answer'] else ''}")
    print(f"   Why: {q['explanation']}")