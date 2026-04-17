# Profil atakującego — „ghost"

## Tożsamość operacyjna

Alias: **ghost** — jedyna znana atrybucja; wszystkie ślady prowadzą do tej samej osoby lub małego zespołu. Brak powiązań z publicznymi grupami APT. Motywacja: kradzież poufnych dokumentów roboczych i kluczy SSH z pojedynczych stacji analityków, prawdopodobnie w celu dalszego ruchu bocznego w sieci docelowej. Atakujący unika głośnych operacji — preferuje długotrwały dostęp nad szybką eksfiltrację dużych wolumenów danych.

## Modus operandi

Ghost stosuje własne narzędzia napisane w Pythonie i unika publicznych frameworków C2, co utrudnia atrybucję na podstawie sygnatur znanych narzędzi. Dostęp początkowy (phishing, exploit usługi brzegowej) leży poza zakresem laboratorium i jest oznaczony jako „poza scope" — interesuje nas wyłącznie faza post-exploitation. Atakujący utrwala dostęp tylko tam, gdzie jest to konieczne: w Rundzie 1 nie stosuje żadnego mechanizmu utrwalenia, co świadczy o wczesnym etapie ewolucji jego narzędzi lub o świadomym minimalizowaniu footprintu przy krótkotrwałych operacjach.

## Ewolucja OPSEC między rundami

Ghost stopniowo doskonali swoje techniki między kolejnymi operacjami. Każda runda reprezentuje nową wersję tego samego zestawu narzędzi:

- **Runda 1 — Naïve.** Brak jakichkolwiek prób ukrycia. Nazwa procesu jest oczywista (`python3 /opt/spyware/spyware.py`), ruch sieciowy jest jawny (HTTP :8080, dane w formacie JSON niezaszyfrowanym), URL serwera C2 jest zakodowany na stałe w źródle próbki. Brak utrwalenia — spyware działa wyłącznie jako proces pierwszoplanowy.

- **Runda 2 — Masquerading.** Proces podszywa się pod wątek jądra systemu (`[kworker/u4:2]`) poprzez wywołanie `prctl(PR_SET_NAME, ...)` i nadpisanie `argv[0]`. Eksfiltracja odbywa się przez HTTPS :443 z przypiętym samopodpisanym certyfikatem RSA (brak PFS — celowa luka OPSEC). Utrwalenie przez `crontab @reboot`. Binarka ELF jest stripowana. Proces pozostaje jednak widoczny w `/proc/<pid>/exe` i dla `ss`/`lsof` — to właśnie jest oś dydaktyczna tej rundy.

- **Runda 3 — Advanced.** Proces jest ukryty przed `/proc` za pomocą biblioteki `libhide.so` ładowanej przez `LD_PRELOAD`. Eksfiltracja odbywa się przez tunel DNS — dane są enkodowane base32 i wysyłane jako subdomeny do `update.ghost-pkg.net`. Wpisy w `/var/log/syslog` są selektywnie kasowane. Antyforenzyka: `touch -t` zmienia `mtime` i `atime` plików narzędzi (ale nie `ctime` — celowa pomyłka atakującego). Utrwalenie przez wpis w `~/.bashrc`.

## Słabości i celowe błędy OPSEC

Każda wersja narzędzi ghost zawiera co najmniej jeden celowy błąd OPSEC, który umożliwia detekcję przez uważnego analityka. Pełna lista tych błędów wraz z wyjaśnieniem mechanizmu detekcji znajduje się wyłącznie w plikach `instructor-notes.md` dla poszczególnych rund — nie są one ujawniane studentom przed zakończeniem analizy. Zadaniem studenta jest samodzielne odkrycie tych słabości na podstawie artefaktów.
