"""Awareness module access, quiz scoring, and non-judgmental learning guidance."""
from __future__ import annotations
import json
from pathlib import Path


def load_json(path: str | Path):
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def generate_learning_recommendations(category_scores: dict[str, float], threshold: int = 80) -> list[dict]:
    module_map = {
        "PHISHING": "phishing-awareness",
        "PASSWORDS": "password-security",
        "MFA": "mfa-basics",
        "SOCIAL ENGINEERING": "social-engineering",
        "SAFE BROWSING": "safe-browsing",
        "RANSOMWARE": "ransomware-awareness",
        "PRIVACY": "data-privacy",
        "WI-FI": "secure-wifi",
        "MOBILE SECURITY": "mobile-security",
        "INCIDENT REPORTING": "incident-reporting",
    }
    recommendations = []
    for category, score in sorted(category_scores.items(), key=lambda item: item[1]):
        value = round(float(score))
        recommendations.append({
            "category": category,
            "score": value,
            "module_id": module_map.get(category, "security-basics"),
            "recommendation": f"Review the {category.title()} awareness module." if value < threshold else "No immediate refresher suggested; revisit during routine learning.",
            "priority": "FOCUS AREA" if value < threshold else "MAINTAIN",
        })
    return recommendations


def score_quiz(questions: list[dict], answers: dict[str, int]) -> dict:
    if not questions:
        return {"overall_score": 0, "label": "No quiz data", "category_scores": {}, "weakest_areas": [], "recommendations": [], "results": []}
    correct = 0
    category_totals: dict[str, list[int]] = {}
    results = []
    for question in questions:
        qid = str(question["id"])
        category = str(question["category"]).upper()
        category_totals.setdefault(category, [0, 0])
        selected = answers.get(qid)
        is_correct = isinstance(selected, int) and selected == int(question["correct_index"])
        if is_correct:
            correct += 1
            category_totals[category][0] += 1
        category_totals[category][1] += 1
        results.append({
            "question_id": qid,
            "category": category,
            "selected_index": selected,
            "correct_index": int(question["correct_index"]),
            "is_correct": is_correct,
            "explanation": question.get("explanation", "Review the related learning module for more context."),
        })
    overall = round(100 * correct / len(questions))
    labels = [(40, "Needs Improvement"), (60, "Basic Awareness"), (80, "Good Awareness"), (100, "Strong Awareness")]
    label = next((name for ceiling, name in labels if overall <= ceiling), "Strong Awareness")
    category_scores = {key: round(100 * value[0] / value[1]) for key, value in category_totals.items() if value[1]}
    weakest = sorted(category_scores, key=category_scores.get)[:3]
    return {
        "overall_score": overall,
        "label": label,
        "correct_answers": correct,
        "total_questions": len(questions),
        "category_scores": category_scores,
        "weakest_areas": weakest,
        "recommendations": generate_learning_recommendations(category_scores),
        "results": results,
        "educational_notice": "This learning score is for self-reflection only; it is not an employee fitness or competency judgment.",
    }
