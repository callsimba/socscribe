import os
import json
import hashlib
import requests
from dotenv import load_dotenv


load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = "mixtral-8x7b-32768"
GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"


description_cache = {}
cache_file = "description_cache.json"


if os.path.exists(cache_file):
    with open(cache_file, 'r') as f:
        try:
            description_cache = json.load(f)
        except json.JSONDecodeError:
            description_cache = {}


def save_cache():
    with open(cache_file, 'w') as f:
        json.dump(description_cache, f, indent=2)


def get_dynamic_description(field, value):
    if not GROQ_API_KEY:
        return "[Error] GROQ_API_KEY not set."

    key_hash = hashlib.sha256(f"{field}|{value}".encode()).hexdigest()
    if key_hash in description_cache:
        return description_cache[key_hash]

    prompt = f"""
You are a cybersecurity assistant helping junior SOC analysts.
Explain what this Wazuh alert field means in simple, professional terms.
Field: {field}
Value: {value}
Keep it short and practical.
"""


    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.5,
        "max_tokens": 100
    }

    try:
        response = requests.post(GROQ_ENDPOINT, headers=headers, json=data)
        result = response.json()
        explanation = result['choices'][0]['message']['content'].strip()
        description_cache[key_hash] = explanation
        save_cache()
        return explanation

    except Exception as e:
        return f"[Groq API Error] {str(e)}"
