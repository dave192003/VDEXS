;RULES

;####################################################################

; HIGH PRIORITY - INFECTED

(defrule high-threat-virus
   (declare (salience 30))
   (not (diagnosis-status (status complete)))
   (system-behavior
      (performance slow)
      (unknown-programs yes)
      (unauthorized-changes yes)
      (file-changes yes))
   =>
   (assert
      (result
         (classification infected)
         (threat-level high)))
   (assert
      (diagnosis-status
         (status complete)))
   (printout t "Possible virus detected. Threat Level: HIGH." crlf))

;####################################################################

(defrule malicious-file
   (declare (salience 30))
   (not (diagnosis-status (status complete)))
   (file-behavior
      (behavior malicious))
   =>
   (assert
      (result
         (classification infected)
         (threat-level high)))
   (assert
      (diagnosis-status
         (status complete)))
   (printout t "Malicious file detected. Threat Level: HIGH." crlf))

;####################################################################

; MEDIUM PRIORITY - SUSPICIOUS

(defrule suspicious-file
   (declare (salience 20))
   (not (diagnosis-status (status complete)))
   (file-characteristics
      (file-source untrusted))
   (file-behavior
      (behavior suspicious))
   =>
   (assert
      (result
         (classification suspicious)
         (threat-level medium)))
   (assert
      (diagnosis-status
         (status complete)))
   (printout t "Suspicious file detected." crlf))

;####################################################################

(defrule medium-threat-virus
   (declare (salience 20))
   (not (diagnosis-status (status complete)))
   (system-behavior
      (performance slow)
      (unknown-programs yes)
      (unauthorized-changes no)
      (file-changes no))
   =>
   (assert
      (result
         (classification suspicious)
         (threat-level medium)))
   (assert
      (diagnosis-status
         (status complete)))
   (printout t "Possible virus activity detected." crlf))

;####################################################################

(defrule suspicious-network
   (declare (salience 20))
   (not (diagnosis-status (status complete)))
   (network-activity
      (unknown-connection yes)
      (unusual-data-transfer yes))
   =>
   (assert
      (result
         (classification suspicious)
         (threat-level medium)))
   (assert
      (diagnosis-status
         (status complete)))
   (printout t "Suspicious network activity detected." crlf))

;####################################################################

;if antivirus is disabled

(defrule antivirus-disabled
   (declare (salience 20))
   (not (diagnosis-status (status complete)))
   (security
      (antivirus disabled))
   =>
   (assert
      (result
         (classification suspicious)
         (threat-level medium)))
   (assert
      (diagnosis-status
         (status complete)))
   (printout t "Antivirus is disabled. System may be at risk." crlf))

;####################################################################

(defrule unauthorized-system-change
   (declare (salience 20))
   (not (diagnosis-status (status complete)))
   (system-behavior
      (unauthorized-changes yes)
      (file-changes no))
   =>
   (assert
      (result
         (classification suspicious)
         (threat-level medium)))
   (assert
      (diagnosis-status
         (status complete)))
   (printout t "Unauthorized system changes detected." crlf))

;####################################################################

; LOW PRIORITY - NOT INFECTED

(defrule system-normal
   (declare (salience 10))
   (not (diagnosis-status (status complete)))
   (system-behavior
      (performance normal)
      (unknown-programs no)
      (unauthorized-changes no)
      (file-changes no))
   (security
      (antivirus enabled))
   =>
   (assert
      (result
         (classification not-infected)
         (threat-level low)))
   (assert
      (diagnosis-status
         (status complete)))
   (printout t "No signs of virus detected." crlf))

;####################################################################

; RECOMMENDED ACTION

(defrule recommend-scan
   (declare (salience 5))
   (diagnosis-status
      (status complete))
   (result
      (classification suspicious))
   =>
   (assert
      (recommended-action
         (action scan)))
   (printout t "Recommended action: Scan the system." crlf))

;####################################################################

(defrule recommend-quarantine
   (declare (salience 5))
   (diagnosis-status
      (status complete))
   (result
      (classification infected)
      (threat-level high))
   =>
   (assert
      (recommended-action
         (action quarantine)))
   (printout t "Recommended action: Quarantine the threat." crlf))