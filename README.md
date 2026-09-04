# Virus Detection Expert System (VDEXS)

A beginner-friendly **Virus Detection Expert System** web application. It is an
**educational demo / input form** — not a real antivirus. It does not scan
files or inspect your computer.

The user manually selects system characteristics on the webpage. The selection
is converted into CLIPS facts and evaluated by CLIPS rules, which produce a
classification, a threat level, and a recommended action.

## How it works

```
HTML/CSS/JS form  ->  Flask (/analyze)  ->  CLIPS (clipspy)  ->  JSON result
```

- `templates/index.html` — the input form (HTML)
- `static/style.css` — styling
- `static/script.js` — collects form values, builds CLIPS facts, calls the backend
- `app.py` — Flask backend that runs the CLIPS engine
- `expert-system/` — the CLIPS knowledge base
  - `templates.clp` — deftemplates (facts)
  - `rules.clp` — diagnosis & recommendation rules
  - `facts.clp` — sample deffacts (test data)
  - `main.clp` — entry point for the CLIPS IDE

## Requirements

- Python 3.x
- Flask and clipspy (see `requirements.txt`)

```bash
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

## Example CLIPS facts produced by the form

```clips
(file-characteristics (file-type executable) (file-source untrusted))
(file-behavior (behavior suspicious))
(system-behavior (performance slow) (unknown-programs yes)
                 (unauthorized-changes no) (file-changes no))
(network-activity (unknown-connection no) (unusual-data-transfer no))
(security (antivirus enabled))
```

Possible results:

- **Classification:** `not-infected` | `suspicious` | `infected`
- **Threat Level:** `low` | `medium` | `high`
- **Recommended Action:** `scan` | `quarantine`