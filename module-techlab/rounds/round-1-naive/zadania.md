# Runda 1 — Naïve: zadania dla studenta

> Pracujesz w kontenerze `analyst-ws`. Stack został uruchomiony komendą:
> ```
> ROUND=1 docker compose --profile full up -d
> ```
> Wszystkie polecenia wykonujesz wewnątrz kontenera `analyst-ws` (np. `docker compose exec analyst-ws bash`).

## Cel

Zidentyfikuj proces spyware działający w kontenerze `victim`, odtwórz sposób jego działania,
udokumentuj IOCs, zatrzymaj go, oraz napisz regułę YARA i krótki raport incydentu.

## Faza red team

### 1. Identyfikacja podejrzanego procesu

- Z `analyst-ws` uzyskaj powłokę w `victim`: `docker compose exec victim bash`.
- Wypisz procesy użytkownika `analyst`: `ps -ef --forest -u analyst`.
- Zidentyfikuj proces zawierający `spyware.py`.
- Sprawdź jego otwarte pliki i sockety: `lsof -p <PID>` oraz `ss -tp | grep <PID>`.
- Zweryfikuj ścieżkę binarki: `readlink /proc/<PID>/exe` i `cat /proc/<PID>/cmdline`.

**Pytanie:** Jaką ścieżkę zwraca `/proc/<PID>/exe`? Czy nazwa procesu w `ps` jest podejrzana?

### 2. Analiza dynamiczna (strace)

- Uruchom nasłuchiwanie wywołań systemowych:
  ```
  strace -f -p <PID> -e trace=openat,read,write,connect,sendto 2> strace.log
  ```
- Odczekaj co najmniej 90 sekund (jeden cykl eksfiltracji), następnie przerwij (`Ctrl+C`).
- Przejrzyj `strace.log` pod kątem:
  - plików otwieranych przez próbkę (`openat`),
  - danych przesyłanych przez sieć (`sendto`, `write` na deskryptorze gniazda).

**Pytanie:** Jakie pliki są odczytywane? Jakie dane trafiają do połączenia sieciowego?

### 3. Analiza ruchu sieciowego (tcpdump)

- Z `analyst-ws` uruchom przechwytywanie:
  ```
  tcpdump -ni eth0 -A -s0 'tcp port 8080' -w /tmp/r1.pcap
  ```
  Odczekaj kilka minut, następnie przerwij (`Ctrl+C`).
- Zbadaj plik pcap:
  ```
  tshark -r /tmp/r1.pcap -Y http.request -T fields -e http.host -e http.request.uri
  tshark -r /tmp/r1.pcap -Y http -T json | head -60
  ```
- Wypisz: adres IP C2, port, URL endpointu, zawartość przesłanego JSON-a.

**Pytanie:** Czy komunikacja jest szyfrowana? Czy można odczytać treść eksfiltrowanych danych?

### 4. Mapa próbki

Odpowiedz krótko na każde z poniższych pytań (1–3 zdania każde):

1. **Co zbiera?** — Wymień typy zbieranych danych.
2. **Jak często wysyła?** — Określ interwał eksfiltracji.
3. **Gdzie wysyła?** — Podaj IP i port serwera C2.
4. **Czy jest utrwalone?** — Sprawdź `crontab -l`, `~/.bashrc`, `/etc/cron.d/`.

## Faza blue team

### 5. Dokumentacja IOCs i mapowanie MITRE ATT&CK

Przygotuj tabelę IOCs w następującym formacie:

| IOC | Wartość | Technika MITRE ATT&CK |
|-----|---------|----------------------|
| Nazwa procesu | ... | ... |
| Ścieżka binarki | ... | ... |
| IP:port C2 | ... | ... |
| Rodzaj wykradanych danych | ... | ... |

Listę dopuszczonych w Rundzie 1 technik znajdziesz w załączniku raportu (sekcja 8).
Każdą obserwację powiąż z co najmniej jednym identyfikatorem MITRE ATT&CK.

### 6. Zatrzymanie i weryfikacja

- Zabij proces spyware w kontenerze `victim`:
  ```
  kill -9 <PID>
  ```
- Wróć do `analyst-ws` i zweryfikuj brak kolejnych żądań HTTP:
  ```
  tcpdump -ni eth0 -A -s0 'tcp port 8080' -w /tmp/r1-after.pcap &
  sleep 120 && kill %1
  tshark -r /tmp/r1-after.pcap -Y http.request | wc -l
  ```
  Oczekiwany wynik: `0`.
- Sprawdź logi serwera C2:
  ```
  docker compose exec c2-server tail -5 /data/received.jsonl
  ```
  Znacznik czasu ostatniego rekordu powinien poprzedzać moment zatrzymania procesu.

### 7. Detekcja — reguła YARA

Napisz regułę YARA w pliku `rules/r1-ghost-naive.yar` dopasowującą próbkę R1. Reguła powinna zawierać:

- sekcję `meta:` z autorem, datą i opisem,
- sekcję `strings:` z co najmniej trzema znaczącymi ciągami
  (np. hardkodowany URL C2, nazwy pól JSON, unikalne fragmenty kodu),
- sekcję `condition:` łączącą ≥ 2 ciągi logiczną koniunkcją (`and`).

Przetestuj regułę na korpusie:
```
pytest tests/test_detection_rules.py -k round_1
```
Oczekiwane wyniki: precision ≥ 0,95 i recall = 1,0.

Możesz też użyć trybu CLI auto-gradera:
```
python -m tests.test_detection_rules --rule rules/r1-ghost-naive.yar --round 1
```

### 8. Raport incydentu (NIST SP 800-61r2)

Napisz krótki raport incydentu (maksymalnie jedna strona A4) zgodny z fazami NIST SP 800-61r2:

| Faza | Opis (co zaobserwowałeś/aś i co wykonałeś/aś) |
|------|------------------------------------------------|
| **Detection** | Jak wykryto incydent? Jakie narzędzia potwierdziły zagrożenie? |
| **Containment** | Jakie kroki podjęto, aby ograniczyć szkody? |
| **Eradication** | Jak usunięto zagrożenie? |
| **Recovery** | Jak przywrócono normalny stan systemu? |

**Załącznik — tabela MITRE ATT&CK:** wypełnij poniższy szablon dla każdej zaobserwowanej techniki:

| Taktyka | Technika (ID) | Dowód w zebranych danych |
|---------|--------------|--------------------------|
| Collection | T1056.001 | ... |
| Collection | T1113 | ... |
| Collection | T1005 | ... |
| Command and Control | T1071.001 | ... |
| Exfiltration | T1041 | ... |

## Kryteria zaliczenia

- Poprawne zidentyfikowanie wszystkich 5 technik MITRE ATT&CK dla Rundy 1.
- Reguła YARA: precyzja ≥ 0,95 i recall = 1,0 na korpusie Rundy 1.
- Raport zgodny z NIST SP 800-61r2 i zawierający załącznik z tabelą MITRE ATT&CK.
