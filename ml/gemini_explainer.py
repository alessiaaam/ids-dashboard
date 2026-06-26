from google import genai
import os
from dotenv import load_dotenv

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

def analyze_session(alerts):
    if not alerts:
        return ""

    attack_summary = []
    for a in alerts:
        attack_summary.append(f"- {a.get('type')}: {a.get('detail')}")
    attacks_text = "\n".join(attack_summary)

    prompt = f"""Esti un expert in securitate cibernetica. Analizeaza urmatoarele alerte detectate de un sistem IDS si scrie o analiza clara in limba romana corecta.

Alerte detectate:
{attacks_text}

Scrie un paragraf de 4-5 propozitii care explica:
1. Ce s-a intamplat in aceasta sesiune
2. Daca atacurile sunt corelate si ce sugereaza impreuna
3. Nivelul de pericol general
4. O recomandare concreta de actiune

Romana corecta, fara formatare, fara cuvinte in engleza, fara liste."""

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        return response.text.strip()
    except Exception as e:
        return ""

def explain_alerts_batch(alerts):
    type_explanations = {}
    for alert in alerts:
        attack_type = alert.get("type")
        if attack_type not in type_explanations:
            type_explanations[attack_type] = ""
    for alert in alerts:
        alert["explanation"] = type_explanations.get(alert.get("type"), "")
    return alerts
