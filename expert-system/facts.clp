(deffacts test-data

   (file-characteristics
      (file-type executable)
      (file-source untrusted))

   (file-behavior
      (behavior suspicious))

   (system-behavior
      (performance slow)
      (unknown-programs yes)
      (unauthorized-changes no)
      (file-changes no))

   (network-activity
      (unknown-connection no)
      (unusual-data-transfer no))

   (security
      (antivirus enabled))
)
