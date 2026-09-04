
; main.clp - entry point for the CLIPS IDE.
; Open CLIPS from the expert-system folder, then run:
;   (load "main.clp")
; It loads the templates, rules and facts, then resets and runs the engine.

(clear)

(load "templates.clp")
(load "rules.clp")
(load "facts.clp")

(reset)
(run)
