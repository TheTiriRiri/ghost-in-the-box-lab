# Briefing — Ghost in the Box

## Kontekst

Jesteś członkiem zespołu reagowania na incydenty (CSIRT) w fikcyjnej firmie analitycznej. Użytkownik `analyst` zgłosił dziwne spowolnienie swojej stacji roboczej `workstation-042` — aplikacje uruchamiają się wolniej niż zwykle, a dysk i sieć wykazują nieoczekiwaną aktywność. Dział bezpieczeństwa podejrzewa infekcję oprogramowaniem szpiegującym (spyware). Masz przed sobą trzy rundy o narastającym poziomie trudności, by potwierdzić obecność zagrożenia, odtworzyć jego działanie i je unieszkodliwić.

## Cel laboratorium

Celem jest przeprowadzenie cyklu red team / blue team dla trzech kolejnych wersji spyware, z których każda stosuje coraz bardziej zaawansowane techniki OPSEC. W każdej rundzie najpierw analizujesz próbkę z perspektywy atakującego (faza red team), a następnie dokumentujesz IOCs, wdrażasz detekcje i piszesz raport incydentu z perspektywy obrońcy (faza blue team). Wszystko dzieje się w izolowanej sieci Docker — brak połączeń do zewnętrznego internetu gwarantuje, że żadne dane nie opuszczą środowiska laboratoryjnego.

## Zasady

Nie modyfikuj kodu próbki spyware — stanowi ona materiał edukacyjny, a nie cel ataku. Każda runda kończy się raportem incydentu zgodnym z modelem NIST SP 800-61r2, zawierającym załącznik z mapowaniem obserwacji na techniki MITRE ATT&CK. Instruktor zachowuje ground truth — porównanie Twoich obserwacji z kluczem odpowiedzi decyduje o zaliczeniu.

## Środowisko

Laboratorium składa się z trzech (lub czterech w Rundzie 3) kontenerów Docker połączonych izolowaną siecią `ghost-net` (podsieć `10.13.37.0/24`):

- **`victim`** — Ubuntu 24.04 z zainstalowanym spyware uruchamianym jako użytkownik `analyst`; to jest stacja robocza `workstation-042`.
- **`c2-server`** — serwer odbierający dane wykradzione przez spyware; nasłuchuje pod adresem `10.13.37.1`.
- **`analyst-ws`** — Twoja stacja kryminalistyczna wyposażona w: `strace`, `ltrace`, `lsof`, `ss`, `tcpdump`, `tshark`/Wireshark, `auditd`/`ausearch`, Volatility 3, `avml`, YARA, Sigma CLI, Suricata, dnscat2 oraz Jupyter Lab.
- **`dns-server`** *(tylko Runda 3)* — serwer autorytatywny DNS obsługujący domenę wykorzystywaną do tunelowania danych.

Każdą rundę uruchamiasz komendą:

```bash
ROUND=<numer> docker compose --profile full up -d
```

## Rundy

| Runda | Nazwa | Kanał eksfiltracji | Poziom OPSEC |
|-------|-------|--------------------|--------------|
| 1 | Naïve | HTTP :8080 (plaintext) | Brak ukrycia |
| 2 | Masquerading | HTTPS :443 | Podszywanie się pod proces jądra |
| 3 | Advanced | Tunel DNS | Ukrywanie procesu, kasowanie logów |

Powodzenia. Atakujący jest już w środku.
