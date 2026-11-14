# Machine-assisted translation - native review pending

errors-forbidden = Sie haben keine Berechtigung für diese Aktion.
errors-auth-failed = Ungültiger Benutzername oder ungültiges Passwort.
errors-router-auth = Der Router hat die Anmeldedaten abgelehnt.
errors-timeout = Zeitüberschreitung bei der Operation.
errors-outbound-refused = kcc verbindet sich nicht mit { $address }: Die Adresse liegt außerhalb der Netze der Einstellung [outbound] allowed_networks. Tragen Sie das Netz des Routers, zum Beispiel 192.168.1.0/24, in allowed_networks in kcc.toml ein (oder das Suffix seines Hostnamens in allowed_suffixes); ein laufendes kcc serve übernimmt die Änderung nach einem Neustart. Cloud-Metadatenadressen sind immer gesperrt.
errors-outbound-metadata = kcc verbindet sich nie mit { $address }: Das ist eine Cloud-Metadatenadresse, die keine Einstellung zulässt.
errors-outbound-loopback = kcc verbindet sich nicht mit { $address }: Loopback-Adressen erfordern [outbound] allow_loopback = true in kcc.toml; ein laufendes kcc serve übernimmt die Änderung nach einem Neustart.
errors-outbound-never = kcc verbindet sich nie mit { $address }: Keine Einstellung lässt diese Art von Adresse zu.
errors-secret-file-permissions = { $path } ist für andere Benutzer lesbar. Führen Sie chmod 600 { $path } aus und versuchen Sie es erneut.
