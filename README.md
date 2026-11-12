# Aláírt firmware-frissítések

Helyben futó Python 3.11+ bemutató, amely egy aláírt firmware-frissítés teljes útját mutatja be a gyártótól az eszközig: Ed25519-cel aláírt manifest, eszközoldali ellenőrzés, visszalépés elleni védelem, öt támadási próba és egy kulcsjelszó-próba. A felület magyar nyelvű, és egyetlen oldalon, lépésről lépésre vezeti végig a nézőt.

## Indítás

```sh
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Ajánlott a Streamlit 1.39 vagy újabb verziója. Régebbi verzión az app működik, de a „Következő lépés" gomb pulzáló kiemelése és a záróképernyő „Vissza" gombjának elhelyezése nem jelenik meg megfelelően.

## Használat

1. A felső űrlapon válasszon egy tetszőleges **firmware-fájlt** (legfeljebb 64 MB), és adja meg az **aláírókulcs jelszavát**.
2. Az **▶ Indítás** gombbal indul a bemutató. Újraindításkor a gomb felirata **↻ Újraindítás**.
3. A **Következő lépés →** és az **← Előző** gombbal lehet haladni a jeleneteken. A már látott jeleneteket újra lehet nézni, ilyenkor a folyamat nem fut tovább.
4. Az utolsó, összesítő jelenetnél a gomb **Befejezés →** lesz, és megnyílik az animált záróképernyő. Az alján halvány **← Vissza** gombbal vissza lehet lépni az összesítésre.
5. A jobb felső **↺ Nullázás** gomb megerősítés után törli a teljes `keys/` mappát, és 0-ra állítja a helyi eszközverziót.

Az első indításkor az app új kulcspárt készít, és a megadott jelszóval védi a privát kulcsot. Későbbi indításokon ugyanazt a jelszót kell megadni. Ha nem egyezik, az app hibát jelez, és a Nullázással lehet új kulcsot kezdeni. Minden futás a telepített verziónál eggyel nagyobb verziószámú csomagot készít.

## Mit mutat a bemutató?

Az oldal három részre oszlik: balra a lépéslista, középen az animált jelenet magyarázattal („Miért fontos?"), jobbra a technikai napló.

| Csoport | Lépések |
|---|---|
| **Gyártó** | 1. Build és tesztelés · 2. Aláírókulcs · 3. Manifest és aláírás · 4. Közzététel |
| **Eszköz** | 5. Letöltés · 6. Bootloader · 7. Csomagellenőrzés · 8. Telepítés |
| **Támadási próbák** | 9. Módosított csomagok · 10. Kulcsjelszó-próba |
| **Eredmény** | 11. Összesítés |

### Az öt eszközoldali ellenőrzés (7. lépés)

1. Gyártói aláírás ellenőrzése a beégetett publikus kulccsal.
2. A csomag felépítése és a kötelező adatok megléte.
3. Az eszközmodell egyezése.
4. A firmware méretének és SHA-256-lenyomatának egyezése a manifesttel.
5. Verzióellenőrzés: csak a telepítettnél újabb verzió fogadható el (visszalépés elleni védelem).

Sikeres ellenőrzés után a 8. lépés bemutatja a telepítést az inaktív A/B partícióra. Elutasított csomag esetén a jelenlegi firmware marad érvényben.

### Az öt támadási próba (9. lépés)

1. A firmware egy bájtjának módosítása.
2. A manifest verzióadatának módosítása.
3. Idegen privát kulccsal aláírt csomag.
4. Régebbi, de érvényesen aláírt verzió visszatelepítése.
5. Az aláírás eltávolítása.

Mindegyik próba az eszköz valódi ellenőrzési eljárásán fut át, és a jelenet megmutatja, hogy az eszköz elutasította-e a csomagot.

### Kulcsjelszó-próba (10. lépés)

Az app a **helyi** `keys/private.json` fájlt próbálja megnyitni gyenge, gyakori jelszavakkal. A próba **összesen legfeljebb 200 jelöltet** vizsgál:

- előbb a `jelszavak.txt` első 200 nem üres sorát,
- ha a fájl rövidebb, a maradék helyet gyakori jelszavak és rövid számkombinációk töltik ki.

Az élő jelölt és a haladási csík a jelenetben látszik, a találat vagy a találat hiánya a naplóban és az összesítésben. A „nincs találat" eredmény csak a kipróbált jelöltekre igaz, nem bizonyítja, hogy a jelszó erős. Éles rendszerben a privát kulcs HSM-ben vagy kulcskezelő szolgáltatásban van, ahol ilyen próba nem fér hozzá.

### Technikai napló

A jobb oldali napló időbélyeggel, címkékkel (`ellenőrzés`, `ok`, `hiba`, `figyelem`, `támadó`, `találat` stb.) rögzít minden eseményt: a kulcs betöltését, a manifest lenyomatát, az öt ellenőrzés elvárt és kapott értékét, a támadási próbák eredményét. A napló legfeljebb az utolsó 500 sort őrzi.

## Fájlok és mappák

| Útvonal | Tartalom |
|---|---|
| `keys/private.json` | Jelszóval titkosított privát aláírókulcs |
| `keys/public.hex` | A publikus kulcs; az eszköz ebben bízik |
| `out/` | Az elkészült, aláírt csomag (firmware, manifest, aláírás) |
| `device/device_state.json` | A helyi eszköz telepített verziója |
| `jelszavak.txt` | A kulcsjelszó-próba szólistája, soronként egy jelölt |

## Animációk

A jelenetek CSS-animációkat használnak (belépő szövegek, mozgó csomag, aláírás-gyűrű, elutasítás-rázkódás, élő jelszópróba, záróképernyő). A rendszer **csökkentett mozgás** beállítása (`prefers-reduced-motion`) kikapcsolja őket.

## Tesztek és teljesítménymérés

```sh
pytest -q
python -c 'from bench import benchmark; print(benchmark())'
```

A `plot_benchmark(benchmark())` matplotlib ábrát ad vissza. A mérés az Ed25519 műveleteit közvetlenül véletlen firmware-bájtokon méri; a frissítési protokoll ezzel szemben a firmware hashét tartalmazó kanonikus manifestet írja alá.

A visszalépés szimulációja ideiglenes, saját aláírókulcsot és az ahhoz tartozó publikus kulcsot használ: az eredeti privát kulcs nélkül nem állítható elő újabb érvényes aláírás. A támadási szimulációk állapota ideiglenes. A hiányzó aláírás formátumhiba az aláírás-ellenőrzés előtt, mert nincs ellenőrizhető aláírás.

## Korlátok

- **Nincs hálózati kommunikáció.** A közzététel és a letöltés lépése szemléltető. Az app nem küld HTTP-kérést, a csomag a helyi `out/` mappán keresztül jut el az ellenőrzőhöz.
- Ez bemutató, nem secure boot megvalósítás. A helyi publikus kulcsot és állapotfájlt a gazdagép fájlrendszerét módosítani képes támadó megváltoztathatja; valódi eszközökön védett bizalmi horgony (gyártáskor beégetett kulcs) és visszalépésálló tárolás szükséges.
- A demó a privát kulcsot jelszóval védett fájlban tárolja. Éles környezetben ez nem elég, ott HSM kell.