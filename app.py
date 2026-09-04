import os
import clips
from flask import Flask, jsonify, render_template, request
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EXPERT_DIR = os.path.join(BASE_DIR, "expert-system")
app = Flask(__name__)

def run_diagnosis(fact_strings):
    """Load templates + rules, assert the given facts, run the engine
    and return the result / recommended action as a plain dict."""
    os.chdir(EXPERT_DIR) 



    env = clips.Environment()
    env.load("templates.clp")
    env.load("rules.clp")
    env.reset()

    for fact_string in fact_strings:
        env.assert_string(fact_string)

    env.run()

    result = {"classification": None, "threat_level": None, "action": None}

    for fact in env.facts():
        template_name = fact.template.name
        if template_name == "result":
            result["classification"] = str(fact["classification"])
            result["threat_level"] = str(fact["threat-level"])
        elif template_name == "recommended-action":
            result["action"] = str(fact["action"])

    return result


@app.route("/")
def index():
    """Render the expert system input form."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """Receive CLIPS facts from the webpage and evaluate them."""
    data = request.get_json(silent=True) or {}
    fact_strings = data.get("facts", [])

    if not fact_strings:
        return jsonify({"error": "No facts were received."}), 400

    try:
        result = run_diagnosis(fact_strings)
    except Exception as exc: 

        return jsonify({"error": f"CLIPS engine failed: {exc}"}), 500

    result["facts"] = fact_strings
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
