import openai
import hashlib
import os
import json
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Set your OpenAI API key from the environment
openai.api_key = os.getenv("OPENAI_API_KEY", "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")

# Store cache to avoid repeated API calls
description_cache = {}
cache_file = "description_cache.json"

# Load cache if it exists
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
    key_hash = hashlib.sha256(f"{field}|{value}".encode()).hexdigest()

    if key_hash in description_cache:
        return description_cache[key_hash]

    prompt = f"""You are a cybersecurity assistant helping junior SOC analysts.
Explain what this Wazuh alert field means in simple, professional terms.
Field: {field}
Value: {value}
Keep it short and practical."""

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=100,
            temperature=0.5
        )
        explanation = response.choices[0].message['content'].strip()
        description_cache[key_hash] = explanation
        save_cache()
        return explanation

    except Exception as e:
        return f"[AI Error] Could not generate explanation: {str(e)}"
