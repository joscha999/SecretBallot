# Wahl prüfen

Jede Person kann selbst prüfen, dass ihre Stimme gezählt wurde und dass das veröffentlichte Ergebnis stimmt. Dafür braucht es kein Vertrauen in den Server oder in die schlüsselhaltenden Personen.

## Vor dem Abstimmen: Fingerabdruck vergleichen

Neben dem Abstimmknopf steht der Fingerabdruck des Wahlgangs (8 Gruppen aus je 4 Zeichen). Die Wahlleitung liest ihn vor dem Öffnen in Mumble vor und blendet ihn im Stream ein. Stimmt er nicht überein, stimme nicht ab und melde dich bei der Wahlleitung. Ein abweichender Fingerabdruck bedeutet, dass jemand die Schlüssel ausgetauscht haben könnte.

## Nach dem Abstimmen: Quittung aufheben

Nach der Abgabe zeigt die Seite deine Quittung. Bricht die Verbindung beim Absenden ab, bietet die Seite "Erneut senden" an; dabei wird genau derselbe verschlüsselte Stimmzettel noch einmal geschickt, damit die Quittung gültig bleibt. Die ersten 16 Zeichen stehen groß da; mit "Quittung kopieren" kopierst du den vollständigen Wert. Notiere sie dir. Die Quittung verrät nicht, wie du gewählt hast.

## Nach dem Schließen: Quittung suchen

Öffne "Öffentliche Liste" und gib deine Quittung (mindestens die ersten 8 Zeichen) in das Suchfeld ein. Fehlt sie, melde dich sofort bei der Wahlleitung; dafür gibt es nach dem Schließen eine Frist von 10 Minuten. Auf der Seite steht außerdem, wie viele Personen abgestimmt haben und wie viele Stimmzettel eingegangen sind. Beide Zahlen müssen gleich sein.

## Ergebnis nachrechnen

Nach der Bekanntgabe veröffentlicht die Wahlleitung zwei Arten von Dateien: das Veröffentlichungspaket (`veroeffentlichung-<id>.json`) und je eine Datei mit dem privaten Entschlüsselungsschlüssel jeder schlüsselhaltenden Person (`entschluesselung-<Rolle>.json`).

1. Öffne "Prüfen" im Wahltool, oder lade den Ordner `SecretBallot.Server/wwwroot` aus dem Quellcode herunter und öffne `pruefen.html` direkt im Browser. Die Seite braucht dann keine Verbindung zum Server.
2. Wähle das Veröffentlichungspaket und alle Entschlüsselungsdateien aus. Trage den Fingerabdruck des Wahlgangs ein, den die Wahlleitung vorgelesen hat (er steht auch im Wahlprotokoll). Optional trägst du deine Quittung ein.
3. Klicke auf "Prüfen".

Die Prüfzeilen bedeuten:

- **Fingerabdruck passt zu den Schlüsseln:** die veröffentlichten Schlüssel ergeben den Fingerabdruck im Paket.
- **Vorgelesener Fingerabdruck:** die veröffentlichten Schlüssel ergeben genau den Fingerabdruck, den die Wahlleitung vor dem Öffnen vorgelesen hat. Erst diese Zeile verbindet die Datei mit dem tatsächlichen Wahlgang; ohne sie könnte jemand ein komplett neu erzeugtes Paket vorlegen.
- **Paket gehört zum Wahlgang** und **Paket und Schicht 0 identisch:** die verschlüsselten Stimmzettel sind die, die beim Schließen vorlagen.
- **Stimmzettel = Abstimmende:** es wurden keine Stimmzettel hinzugefügt oder entfernt.
- **Einheitliche Größe der Stimmzettel:** alle Stimmzettel sind gleich lang, ihre Länge verrät also nichts.
- **Schicht 1 bis N:** jede schlüsselhaltende Person hat ihre Schicht ehrlich entschlüsselt; die Seite rechnet das mit dem veröffentlichten Schlüssel nach.
- **Auszählung nachgerechnet:** die eigene Auszählung ergibt genau das festgeschriebene Ergebnis.
- **Unterschrift ...:** jede schlüsselhaltende Person hat genau dieses Ergebnis unterschrieben.

Darunter stehen die Prüfsumme des Ergebnisdokuments und die Fingerabdrücke der Signaturschlüssel; vergleiche sie mit dem Wahlprotokoll. Danach folgt das nachgerechnete Ergebnis, jeweils mit und ohne leere Stimmzettel in der Mehrheitsbasis.

## Ausgelieferte Dateien prüfen

Vor dem Parteitag wird eine Liste mit den SHA-256-Prüfsummen aller Dateien veröffentlicht, die das Wahltool an den Browser ausliefert. Wer mag, lädt die Dateien vom Server herunter und vergleicht, zum Beispiel unter Linux mit `sha256sum index.html js/ballot-crypto.js`. Eine abweichende Prüfsumme während des Parteitags ist ein Sicherheitsvorfall und muss sofort der Versammlungsleitung gemeldet werden.
