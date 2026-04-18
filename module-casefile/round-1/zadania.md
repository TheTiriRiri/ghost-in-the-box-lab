# Runda 1 — Naïve: zadania (wariant casefile / offline)

> Wariant do pracy bez Dockera. Otrzymałeś/aś paczkę artefaktów:
>
> - `network-capture.pcap` — ruch sieciowy z momentu infekcji,
> - `auth.log`, `syslog` — logi systemowe ze stacji `workstation-042`,
> - `process-list.txt` — migawka `ps -elf` z zainfekowanej stacji,
> - `stolen-data-sample.json` — fragmenty danych odebrane przez C2 (jedna linia = jeden POST),
> - `yara-corpus/` — próbki pozytywne i negatywne do auto-oceny Twojej reguły YARA.
>
> Używasz Wireshark/tshark, `yara`, dowolnego edytora tekstu. Docker nie jest wymagany.

## Cel

Na podstawie artefaktów odtwórz działanie spyware z Rundy 1, udokumentuj IOCs,
napisz regułę YARA i raport incydentu.

## Faza red team

### 1. Analiza `process-list.txt`

- Otwórz plik `process-list.txt` w edytorze lub przejrzyj go komendą `cat process-list.txt`.
- Wypisz procesy nienależące do typowego zestawu systemowego (porównaj z wiedzą o usługach Ubuntu 24).
- Zidentyfikuj proces ze ścieżką `/opt/spyware/spyware.py`. Podaj PID, PPID, UID i czas startu.

**Pytanie:** Czy nazwa procesu w kolumnie CMD jest podejrzana? Co mówi PPID o tym, skąd został uruchomiony?

### 2. Analiza `network-capture.pcap`

- Wczytaj `network-capture.pcap` w Wireshark lub użyj tshark:
  ```
  tshark -r network-capture.pcap -Y http.request -T fields \
    -e ip.src -e ip.dst -e tcp.dstport -e http.request.uri
  ```
- Wyciągnij treść żądania (Wireshark: Follow → TCP Stream, tshark: `-T json`):
  ```
  tshark -r network-capture.pcap -Y http -T json | head -80
  ```
- Odpowiedz: IP źródłowe i docelowe, port, URL endpointu, Content-Type, zawartość JSON.

**Pytanie:** Czy komunikacja jest szyfrowana? Czy można odczytać treść eksfiltrowanych danych bezpośrednio z pcap?

### 3. Korelacja z `stolen-data-sample.json`

- Policz liczbę rekordów:
  ```
  wc -l stolen-data-sample.json
  ```
- Sprawdź pola `ts_epoch` kolejnych rekordów i wyznacz interwał eksfiltracji.
- Wyszczególnij: jakie kategorie plików są wykradane (pole `files`), ile klawiszy trafia do jednego rekordu.

**Pytanie:** Jaki jest interwał między kolejnymi POST-ami? Jakie pliki systemowe użytkownika są eksfiltrowane?

### 4. Analiza logów (`auth.log` i `syslog`)

- W `auth.log` odszukaj wiersz z `New session` dla użytkownika `analyst` — wyznacza czas logowania.
- W `syslog` odszukaj wpisy z `DST=10.13.37.1` — to ślady połączeń jądra do C2.
- Zbuduj krótką oś czasu:
  - logowanie użytkownika,
  - start procesu spyware (na podstawie `process-list.txt` START),
  - pierwszy POST do C2 (na podstawie `network-capture.pcap`).

## Faza blue team

### 5. Tabela IOC + mapowanie MITRE ATT&CK

Sporządź tabelę IOCs w formacie:

| IOC | Wartość | Źródło | MITRE ATT&CK |
|-----|---------|--------|-------------|
| Adres C2 | `10.13.37.1:8080` | pcap | T1071.001 |
| Ścieżka procesu | `/opt/spyware/spyware.py` | process-list.txt | T1059.006 |
| Wykradane pliki | `.bash_history`, `.ssh/id_rsa`, `Documents/` | stolen-data-sample.json | T1005 |
| Przechwytywanie klawiszy | pole `keys` w POST | stolen-data-sample.json | T1056.001 |
| Zrzuty ekranu | pole `screenshot_bytes` w POST | stolen-data-sample.json | T1113 |

Dopuszczony zestaw technik dla Rundy 1 (ekskluzywnie): **T1056.001, T1113, T1005, T1071.001, T1041**.
Jeśli deklarujesz coś spoza tej listy — uzasadnij na podstawie artefaktów.

### 6. Reguła YARA

Napisz regułę YARA w pliku `r1-ghost-naive.yar` dopasowującą próbkę R1
(dostępną jako `yara-corpus/positive/spyware-r1.py`), **nie** dopasowującą żadnej
próbki z `yara-corpus/negative/`. Minimalne wymagania:

- sekcja `meta:` z autorem i opisem,
- sekcja `strings:` z co najmniej trzema odrębnym ciągami
  (np. hardkodowany URL C2, unikalne pole JSON, nagłówek laboratorium),
- sekcja `condition:` łącząca ≥ 2 ciągi logiczną koniunkcją (`and`).

Auto-oceń regułę lokalnie:
```
python -m tests.test_detection_rules --rule r1-ghost-naive.yar --round 1
```
Wymaga: precyzja ≥ 0,95 i recall = 1,0.

Możesz też uruchomić `yara` bezpośrednio:
```
yara r1-ghost-naive.yar yara-corpus/positive/
yara r1-ghost-naive.yar yara-corpus/negative/
```
Pierwszy powinien zwrócić dopasowanie, drugi — brak dopasowań.

### 7. Raport incydentu (NIST SP 800-61r2)

Dostarcz jednostronicowy raport opisujący cztery fazy:

| Faza | Opis (co zaobserwowałeś/aś i co wykonałeś/aś) |
|------|------------------------------------------------|
| **Detection** | Jak wykryto zagrożenie? Które artefakty potwierdziły infekcję? |
| **Containment** | Jakie kroki ograniczyłyby szkody (np. izolacja hosta, kill procesu)? |
| **Eradication** | Jak usunięto by zagrożenie? Jakie pliki i procesy należy usunąć? |
| **Recovery** | Jak przywrócić normalny stan systemu? Co sprawdzić po oczyszczeniu? |

**Załącznik — tabela MITRE ATT&CK:** uzupełnij poniższy szablon dla każdej zaobserwowanej techniki:

| Taktyka | Technika (ID) | Dowód w artefaktach |
|---------|--------------|---------------------|
| Collection | T1056.001 | pole `keys` w stolen-data-sample.json |
| Collection | T1113 | pole `screenshot_bytes` w stolen-data-sample.json |
| Collection | T1005 | pole `files` w stolen-data-sample.json |
| Command and Control | T1071.001 | POST /collect widoczny w network-capture.pcap |
| Exfiltration | T1041 | eksfiltracja przez ten sam kanał HTTP co C2 |

## Kryteria zaliczenia

- Poprawnie zidentyfikowane wszystkie 5 technik MITRE ATT&CK dla Rundy 1.
- Reguła YARA: precyzja ≥ 0,95 i recall = 1,0 na korpusie Rundy 1.
- Raport zgodny z NIST SP 800-61r2 i zawierający załącznik z tabelą MITRE ATT&CK.
