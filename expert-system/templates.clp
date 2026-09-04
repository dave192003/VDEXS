
;TEMPLATES
(deftemplate file-characteristics
    (slot file-type)
    (slot file-source)
)

(deftemplate file-behavior
    (slot behavior)
)

(deftemplate system-behavior
    (slot performance)    
    (slot unknown-programs)    
    (slot unauthorized-changes)    
    (slot file-changes)        
)

(deftemplate network-activity
    ( slot unknown-connection)
    ( slot unusual-data-transfer)
)

(deftemplate security
    (slot antivirus)
)

(deftemplate threat-level
    (slot level)
)

(deftemplate recommended-action
    (slot action)
)


(deftemplate diagnosis-status
    (slot status)
)

(deftemplate result
    (slot classification)
    (slot threat-level)
)