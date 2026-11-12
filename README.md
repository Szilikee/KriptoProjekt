# Aláírt firmware-frissítések

Helyben futó Python 3.11+ bemutató Ed25519-cel aláírt firmware-manifesztekről, eszközoldali ellenőrzésről, visszalépés elleni védelemről, támadásszimulációról és teljesítménymérésről.

## Indítás

```sh
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Az **Aláíró** fülön adjon meg jelszót, generáljon kulcspárt, töltsön fel firmware-t és hozzon létre csomagot. A privát kulcs titkosítva a `keys/private.json` fájlban, a publikus kulcs a `keys/public.hex` fájlban található. Új kulcspár generálása felülírja a régit. A három csomagfájl az `out/` könyvtárba kerül, és a felületről külön le is tölthető. A grafikus adatfolyam és az ellenőrzési sáv szemléltető animációt használ; a mozgás a rendszer csökkentett mozgás beállításával kikapcsolható.

Az **Eszköz** fülön töltse fel az `out/firmware.bin` és az `out/manifest.json` fájlokat, és válassza az ellenőrzést és telepítést. Az eszköz a `keys/public.hex` kulcsban bízik, és a `device/device_state.json` fájlban tárolja a verziót. A visszalépés elutasításához először telepítsen nagyobb verziót, majd próbáljon egy régebbi, érvényesen aláírt csomagot. A visszaállító gomb kizárólag demócélra szolgál.

## Mit lát a felhasználó?

- **Hogyan működik?** A három szereplő adatfolyama, az öt ellenőrzés, előadási kapcsolatok és fogalomtár.
- **Aláíró:** kulcsgenerálás, csomagkészítés, publikus kulcs ujjlenyomata, aláírt kanonikus JSON, firmware-hash és aláírás.
- **Eszköz:** az állapot és a visszalépés elleni védelem, telepítés, részletes ellenőrzési nyomvonal és technikai napló.
- **Támadás:** öt elkülönített szimuláció magyarázattal, valamint élő firmware-módosítás és hash-összehasonlítás.

A tanári részletes útmutató: [`docs/walkthrough_hu.md`](docs/walkthrough_hu.md).

## Tesztek és teljesítménymérés

```sh
pytest -q
python -c 'from bench import benchmark; print(benchmark())'
```

A `plot_benchmark(benchmark())` matplotlib ábrát ad vissza. A mérés az Ed25519 műveleteit közvetlenül véletlen firmware-bájtokon méri; a frissítési protokoll ezzel szemben a firmware hashét tartalmazó kanonikus manifestet írja alá.

A visszalépés szimulációja ideiglenes, saját aláírókulcsot és az ahhoz tartozó publikus kulcsot használ: az eredeti privát kulcs nélkül nem állítható elő újabb érvényes aláírás. Az összes szimuláció állapota ideiglenes. A hiányzó aláírás formátumhiba az aláírás-ellenőrzés előtt, mert nincs ellenőrizhető aláírás.

Ez bemutató, nem secure boot megvalósítás. A helyi publikus kulcsot és állapotfájlt a gazdagép fájlrendszerét módosítani képes támadó megváltoztathatja; valódi eszközökön védett bizalmi horgony és visszalépésálló tárolás szükséges.
