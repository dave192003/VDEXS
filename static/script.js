/* ============================================================
   Virus Detection Expert System - Frontend logic
   Collects the form values, converts them into CLIPS facts,
   sends them to the Flask backend (/analyze) and shows the
   classification / threat level / recommended action.
   ============================================================ */

"use strict";

const form = document.getElementById("analysis-form");
const resetBtn = document.getElementById("reset-btn");
const resultSection = document.getElementById("result-section");
const resultError = document.getElementById("result-error");
const resultContent = document.getElementById("result-content");
const classificationEl = document.getElementById("result-classification");
const threatEl = document.getElementById("result-threat");
const actionEl = document.getElementById("result-action");
const analyzeBtn = form.querySelector(".btn-primary");

const CLASSIFICATION_LABELS = {
    "not-infected": "Not Infected",
    "suspicious": "Suspicious",
    "infected": "Infected",
};

const THREAT_LABELS = {
    "low": "Low",
    "medium": "Medium",
    "high": "High",
};

const ACTION_LABELS = {
    "scan": "Scan the system.",
    "quarantine": "Quarantine the threat.",
};

/* Severity color class per classification or threat level */
const SEVERITY_CLASS = {
    "not-infected": "sev-safe",
    "suspicious": "sev-warning",
    "infected": "sev-danger",
    "low": "sev-safe",
    "medium": "sev-warning",
    "high": "sev-danger",
};

/*Collect values from the form */

function getSelectValue(id) {
    return document.getElementById(id).value;
}

function getRadioValue(name) {
    const checked = document.querySelector(`input[name="${name}"]:checked`);
    return checked ? checked.value : null;
}


function buildClipsFacts(values) {
    return [
        `(file-characteristics (file-type ${values["file-type"]}) (file-source ${values["file-source"]}))`,
        `(file-behavior (behavior ${values["behavior"]}))`,
        `(system-behavior (performance ${values["performance"]}) (unknown-programs ${values["unknown-programs"]}) (unauthorized-changes ${values["unauthorized-changes"]}) (file-changes ${values["file-changes"]}))`,
        `(network-activity (unknown-connection ${values["unknown-connection"]}) (unusual-data-transfer ${values["unusual-data-transfer"]}))`,
        `(security (antivirus ${values["antivirus"]}))`,
    ];
}

/* Show / reset the result section  */

function applyCardSeverity(severity) {
    resultSection.classList.remove("sev-safe", "sev-warning", "sev-danger");
    if (severity && SEVERITY_CLASS[severity]) {
        resultSection.classList.add(SEVERITY_CLASS[severity]);
    }
}

function showResult(data) {
    resultSection.hidden = false;

    if (data.error) {
        // Backend could not process the facts
        resultError.textContent = "Error: " + data.error;
        resultError.hidden = false;
        resultContent.hidden = true;
        applyCardSeverity(null);
        return;
    }

    resultError.hidden = true;
    resultContent.hidden = false;

    const classification = data.classification;
    const threat = data.threat_level;
    const action = data.action;

    if (!classification) {
        applyCardSeverity(null);
        classificationEl.textContent = "No matching rule";
        classificationEl.className = "result-value sev-neutral";
        threatEl.textContent = "Unknown";
        threatEl.className = "result-value sev-neutral";
        actionEl.textContent = "Try selecting different characteristics.";
        actionEl.className = "result-value sev-neutral";
    } else {
        applyCardSeverity(classification);
        classificationEl.textContent = CLASSIFICATION_LABELS[classification] || classification;
        classificationEl.className = "result-value " + (SEVERITY_CLASS[classification] || "sev-neutral");

        threatEl.textContent = THREAT_LABELS[threat] || threat || "Unknown";
        threatEl.className = "result-value " + (SEVERITY_CLASS[threat] || "sev-neutral");

        actionEl.textContent = action ? (ACTION_LABELS[action] || action) : "No action required.";
        actionEl.className = "result-value " + (SEVERITY_CLASS[threat] || "sev-neutral");
    }
}

/*  Form submission */

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    // Collect all selected values 
    const values = {
        "file-type": getSelectValue("file-type"),
        "file-source": getSelectValue("file-source"),
        "behavior": getSelectValue("behavior"),
        "performance": getRadioValue("performance"),
        "unknown-programs": getRadioValue("unknown-programs"),
        "unauthorized-changes": getRadioValue("unauthorized-changes"),
        "file-changes": getRadioValue("file-changes"),
        "unknown-connection": getRadioValue("unknown-connection"),
        "unusual-data-transfer": getRadioValue("unusual-data-transfer"),
        "antivirus": getRadioValue("antivirus"),
    };

    // Basic check: every question must have an answer
    for (const [key, value] of Object.entries(values)) {
        if (!value) {
            alert(`Please answer: ${key.replace(/-/g, " ")}`);
            return;
        }
    }

    // Build the CLIPS facts from the selected values
    const facts = buildClipsFacts(values);

    // sends the facts to the Flask backend, which runs the CLIPS engine
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "Analyzing...";

    try {
        const response = await fetch("/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ facts: facts }),
        });
        const data = await response.json();
        showResult(data);
    } catch (err) {
        // if   Backend not reachable 
        showResult({ error: "Could not reach the analysis server. Make sure app.py is running (python app.py), then try again." });
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = "Analyze System";
    }
});

/* ---------- Reset form ---------- */

resetBtn.addEventListener("click", () => {
    form.reset();                    // back to the default selections
    resultSection.hidden = true;     // hide the result section again
    resultError.hidden = true;
    applyCardSeverity(null);         // remove the severity background
});
