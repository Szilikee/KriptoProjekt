# Aláírt firmware-frissítés: tanári áttekintés

## 1. Mi a probléma, és miért?

Egy eszköz firmware-frissítése sérülhet vagy illetéktelenül módosulhat. Nem elegendő, hogy egy fájl megérkezett: az eszköznek meg kell győződnie arról, hogy a gyártó által jóváhagyott, neki szánt és az aktuálisnál újabb tartalmat kapta. A digitális aláírás a manifest hitelességét, a benne foglalt hash a firmware sértetlenségét ellenőrzi.

## 2. A három szereplő

A **gyártó/aláíró** létrehozza a kulcspárt és aláírja a kiadási adatokat. Az **eszköz** az előre megbízhatónak tekintett publikus kulccsal ellenőrzi a csomagot, majd a helyi állományban rögzíti a verziót. A **felület** mindkét szerep és a támadások lépéseit teszi bemutathatóvá; nem önálló bizalmi horgony.

## 3. Egy teljes körfolyamat lépésről lépésre

1. Az Aláíró fülön megadott jelszóval a generált privát kulcs titkosítva a `keys/private.json` fájlba kerül. A `keys/public.hex` a publikus kulcs nyers bájtjainak hexadecimális alakja.
2. A felhasználó firmware-t, eszközmodellt, numerikus verziót, verziónevet és dátumot ad meg. A program kiszámítja a firmware méretét és SHA-256 hashét, és létrehozza a manifestet.
3. Az aláíró a rendezett kulcsú, felesleges szóközök nélküli kanonikus JSON bájtjait írja alá Ed25519-cel. Az aláírásmező nem része az aláírt bájtsorozatnak.
4. Az `out/firmware.bin` a firmware; az `out/manifest.json` a manifestet és a base64 aláírást tartalmazza. Az `out/signature.b64` ugyanezt az aláírást külön is tartalmazza; az eszközfelület a manifestben levő értéket használja.
5. Az Eszköz fülre a `firmware.bin` és a `manifest.json` töltendő fel. Az ellenőrzés a `keys/public.hex` kulcsot használja, az elfogadott verziót a `device/device_state.json` fájlba atomikusan írja. Hiányzó állapot esetén a kiinduló verzió 0.

## 4. Az öt ellenőrzés és mindegyik célja

1. **Aláírás:** a publikus kulccsal ellenőrizhető, hogy a manifestet a megfelelő privát kulccsal írták-e alá, és nem módosult-e. A hiányzó aláírás már itt formátumhibát okoz, mert nincs mit ellenőrizni.
2. **Formátum:** csak az 1-es formátumverzió és az előírt, helyes típusú mezők fogadhatók el.
3. **Modell:** a firmware csak a manifestben megadott eszközmodellre telepíthető.
4. **Méret és hash:** a tényleges firmware egyezik az aláírt manifestben rögzített mérettel és SHA-256 értékkel.
5. **Verzió:** a csomag numerikus verziójának szigorúan nagyobbnak kell lennie a telepítettnél. Így nem települ vissza egy korábbi, esetleg sérülékeny verzió.

Az ellenőrzés az első hibánál megáll. Elfogadáskor történik meg az állapot atomikus cseréje.

## 5. Mi történik támadás esetén?

| Módosítás | Várt elutasítás | Miért? |
|---|---|---|
| Egy firmware-bit megváltozik | HashMismatch | A manifest aláírása maradhat érvényes, de a firmware hash-e megváltozik. |
| A verziószöveg megváltozik | SignatureInvalid | A megváltozott manifestre a régi aláírás nem érvényes. |
| Más kulcs írja alá | SignatureInvalid | Az aláírás nem ellenőrizhető a megbízható publikus kulccsal. |
| Korábbi, érvényes verzió | RollbackRejected | A verzió nem nagyobb a már telepítettnél. |
| Hiányzó aláírás | FormatInvalid | Hiányzó aláírást nem lehet ellenőrizni. |

A szimulátor nem módosítja a valódi eszközállapotot. A visszalépés esetén külön ideiglenes kulcspárt használ, mert az eredeti privát kulcsot nem kapja meg; mindkét verziót ezzel írja alá, és az ideiglenes eszköz a hozzá tartozó publikus kulcsban bízik.

## 6. Hogyan kell reprodukálni a demót?

Telepítse a függőségeket a README szerint, majd indítsa a `streamlit run app.py` parancsot. Az Aláíró fülön adjon meg jelszót, generáljon kulcspárt, válasszon egy nem üres firmware-fájlt, majd készítsen a `demo-device` modellhez 3-as verziójú csomagot. Másolja el a csomagfájlokat, ha később is szükség lesz rájuk: az új csomag felülírja az `out/` tartalmát.

1. **Érvényes telepítés:** az Eszköz fülön állítsa vissza az állapotot, töltse fel a 3-as `firmware.bin` és `manifest.json` fájlokat, majd ellenőrizzen. Zöld eredmény, öt sikeres lépés és 0 → 3 állapotváltozás látható.
2. **Módosított firmware:** ugyanazokat a fájlokat feltöltve a Támadás fülön jelölje be az egy bájtot módosító lehetőséget. A piros `HashMismatch` a negyedik lépésnél jelenik meg, az állapot nem változik. A jelölést ezután vegye ki.
3. **Visszalépés:** az Aláíró fülön ugyanazzal a kulccsal készítsen 2-es verziójú csomagot, majd töltse fel az új fájlokat az Eszköz fülön. A 3-as telepített verzió mellett a piros `RollbackRejected` az ötödik lépésnél jelenik meg.

A Támadás fül ötös szimulációjához használjon ép, megfelelő kulccsal aláírt, megfelelő modellű csomagot, és indítsa el a szimulációt. Az öt sor sikeres; az egyes forgatókönyvek részletei kinyithatók. A szimulációs visszalépés külön állapotot és kulcsot használ.

## 7. Korlátok

Nincs TPM vagy HSM, hardveres integráció vagy secure boot. A helyi állapotfájlt és publikus kulcsot a gazdagéphez hozzáférő támadó módosíthatja, ezért ez a demó nem ad hardveresen védett bizalmi horgonyt vagy visszalépés elleni tárolást. Az Ed25519 nem posztkvantum algoritmus. A frissítési szállítás nincs megvalósítva.

## 8. Mit tanultam

*[A hallgató saját összefoglalójának helye.]*
