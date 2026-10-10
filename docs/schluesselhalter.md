# Anleitung für schlüsselhaltende Personen

Als schlüsselhaltende Person hältst du einen Teil des Schlüssels, mit dem die Stimmzettel einer geheimen Wahl verschlüsselt werden. Nur alle schlüsselhaltenden Personen gemeinsam können die Stimmzettel lesen, und niemand von euch erfährt, wer welchen Stimmzettel abgegeben hat. Deine Schlüssel ersetzen deine Unterschrift unter dem Wahlprotokoll.

## Vorbereitung

- Nutze deinen eigenen Rechner mit einem aktuellen Browser (Firefox, Chrome, Edge oder Safari). Kein fremder oder gemeinsam genutzter Rechner.
- Überlege dir ein starkes Passwort mit mindestens 12 Zeichen und schreibe es auf Papier auf.
- Halte einen sicheren Ablageort für die Sicherungsdatei bereit, zusätzlich am besten einen USB-Stick.
- Du darfst den Server des Wahltools nicht betreiben und keinen Zugriff darauf haben.
- Die Verwaltung muss dich vorher mit deinem Piratenlogin-Benutzernamen als schlüsselhaltende Person eingetragen haben.

## Schlüssel erzeugen

1. Öffne das Wahltool und melde dich oben mit deinem Piratenlogin an.
2. Öffne "Schlüsselverwaltung". Oben stehen deine Rolle und deine Position in der Reihenfolge.
3. Gib zweimal dein Passwort ein und klicke auf "Schlüssel erzeugen und Sicherung herunterladen". Der Browser speichert eine Datei `schluessel-<Rolle>.json`.
4. Lege die Datei an deinem sicheren Ort ab und kopiere sie auf den USB-Stick.
5. Wähle die Datei im nächsten Schritt erneut aus, gib das Passwort ein und klicke auf "Sicherung prüfen und Schlüssel registrieren". Erst wenn die Datei sich mit deinem Passwort öffnen lässt, werden deine öffentlichen Schlüssel an den Server geschickt.
6. Vergleiche die angezeigten Fingerabdrücke (Server und Browser). Stimmen beide Paare überein, klicke auf "Fingerabdrücke stimmen überein, bestätigen". Weichen sie ab, bestätige nicht und melde dich sofort bei der Wahlleitung und der Verwaltung.

Ohne die Sicherungsdatei und das Passwort kann ein Wahlgang nicht ausgezählt werden. Geht beides verloren, ist der Wahlgang ungültig.

## Nach einem Neustart des Servers

Der Server speichert nichts dauerhaft. Nach einem Neustart trägt die Verwaltung die schlüsselhaltenden Personen neu ein. Öffne dann die Schlüsselverwaltung, wähle unter "Sicherung laden" deine Sicherungsdatei aus und gib dein Passwort ein. Deine Schlüssel werden neu registriert; danach vergleichst und bestätigst du die Fingerabdrücke wie oben.

## Für die Wahlleitung: Wahlgang durchführen

1. Die Verwaltung legt den Wahlgang an. In der Schlüsselverwaltung erscheint er als "vorbereitet" mit seinem Fingerabdruck.
2. Lies den Fingerabdruck in Mumble vor und lass ihn im Stream einblenden. Sag vorher an, wie leere Stimmzettel bei der Mehrheit gezählt werden.
3. Klicke auf "Wahlgang öffnen". Das geht nur, wenn alle schlüsselhaltenden Personen ihre Schlüssel bestätigt haben.
4. Mit "Aktualisieren" siehst du die Zahl der abgegebenen Stimmen.
5. Klicke am Ende auf "Wahlgang schließen".
6. Sag die öffentliche Liste an und gib den Abstimmenden 10 Minuten Zeit, ihre Quittung zu suchen. Fehlt eine Quittung nachweislich, ist der Wahlgang ungültig.

## Auszählung

1. Lade oben deine Sicherungsdatei mit deinem Passwort.
2. Prüfe beim Wahlgang, dass die Zahl der Stimmzettel gleich der Zahl der Abstimmenden ist. Wird eine Abweichung angezeigt, ist der Wahlgang ungültig.
3. Wenn du an der Reihe bist, klicke auf "Meine Schicht entschlüsseln". Die Seite prüft vorher, ob die geladene Sicherung zu diesem Wahlgang gehört. Lassen sich einzelne Stimmzettel nicht entschlüsseln, zeigt sie die Zahl an und lädt erst nach einer Bestätigung hoch; sprich bei mehr als Einzelfällen vorher mit der Wahlleitung. Die Reihenfolge ist die Reihenfolge in der Liste; die nächste Person sieht danach ihren Knopf. Es muss nicht alles in einer Sitzung passieren.
4. Nach der letzten Schicht zeigt die Seite die Auszählung, jeweils mit und ohne leere Stimmzettel in der Mehrheitsbasis.
5. Die letzte Person in der Reihenfolge klickt auf "Ergebnis festschreiben".
6. Jede Person prüft die Zahlen und klickt auf "Ergebnis prüfen und unterschreiben". Deine Seite rechnet das Ergebnis selbst nach und warnt, wenn das festgeschriebene Ergebnis abweicht. Dann nicht unterschreiben.

## Veröffentlichung

Nach der Bekanntgabe des Ergebnisses lädt jede Person das Veröffentlichungspaket herunter. Wenn an diesem Tag kein weiterer Wahlgang mit denselben Schlüsseln mehr folgt (zum Beispiel keine Stichwahl), exportiert jede Person ihren privaten Entschlüsselungsschlüssel (Datei `entschluesselung-<Rolle>.json`) mit "Privaten Schlüssel exportieren und stilllegen". Gib die Datei der Wahlleitung; sie veröffentlicht das Paket und alle Entschlüsselungsschlüssel zusammen. Damit kann jede Person das Ergebnis nachrechnen. Deinen Signaturschlüssel gibst du nicht heraus.

Beim Export legt der Server deine Schlüssel still. Ein veröffentlichter Schlüssel darf nie wieder für einen Wahlgang verwendet werden, denn mit ihm könnte jede Person die Stimmzettel lesen. Für weitere Wahlgänge erzeugst du neue Schlüssel und eine neue Sicherung. Lade die alte Sicherungsdatei danach nicht mehr, auch nicht nach einem Neustart des Servers: der Server vergisst bei einem Neustart, welche Schlüssel stillgelegt wurden.

Für das Wahlprotokoll: Die Prüfseite zeigt die Prüfsumme des Ergebnisdokuments und die Fingerabdrücke aller Signaturschlüssel. Trage beides zusammen mit dem vorgelesenen Fingerabdruck des Wahlgangs ins Protokoll ein.

## Was tun, wenn

- **der Fingerabdruck abweicht:** nicht bestätigen bzw. nicht öffnen, sofort Wahlleitung und Verwaltung informieren.
- **die Zahl der Stimmzettel nicht zur Zahl der Abstimmenden passt:** der Wahlgang ist ungültig und wird wiederholt.
- **eine Quittung fehlt:** die Wahlleitung prüft das; bestätigt sich der Fehler, ist der Wahlgang ungültig.
- **der Server während eines offenen Wahlgangs neu startet:** der Wahlgang ist ungültig und wird wiederholt.
- **deine Sicherungsdatei oder dein Passwort verloren ist:** ein bereits geschlossener Wahlgang kann nicht ausgezählt werden und ist ungültig. Für künftige Wahlgänge trägt die Verwaltung dich neu ein und du erzeugst neue Schlüssel.
