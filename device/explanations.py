"""Hungarian teaching texts for the update verification process."""

CHECK_EXPLANATIONS = {
    'Aláírás ellenőrzése': {'what': 'Az eszköz a megbízható publikus kulccsal ellenőrzi a manifest aláírását.', 'why': 'Ez segít felismerni a jogosulatlanul aláírt vagy módosított manifestet.'},
    'Formátum ellenőrzése': {'what': 'Az eszköz ellenőrzi a manifest formátumverzióját és kötelező mezőit.', 'why': 'Csak értelmezhető, támogatott formátumú adat alapján szabad dönteni.'},
    'Eszközmodell ellenőrzése': {'what': 'Az eszköz összeveti a saját modelljét a manifestben szereplő modellel.', 'why': 'Ezzel elkerülhető, hogy más hardverhez készült firmware kerüljön az eszközre.'},
    'Méret és hash ellenőrzése': {'what': 'Az eszköz összehasonlítja a firmware méretét és SHA-256 hashét a manifest adataival.', 'why': 'Ez felismeri a firmware sérülését vagy módosítását akkor is, ha a manifest aláírása érvényes.'},
    'Verzió ellenőrzése': {'what': 'Az eszköz megköveteli, hogy a csomag verziója nagyobb legyen a telepítettnél.', 'why': 'A rollback elleni védelem megakadályozza egy régi, akár sérülékeny verzió visszatelepítését.'},
}

EXCEPTION_EXPLANATIONS = {
    'SignatureInvalid': 'A manifestet módosították, más kulccsal írták alá, vagy az aláírás sérült. Az elutasítás megakadályozza, hogy nem hiteles kiadást fogadjunk el.',
    'FormatInvalid': 'Hiányzik vagy hibás az aláírás, illetve a manifest formátuma nem támogatott vagy hiányos. Az elutasítás megakadályozza, hogy értelmezhetetlen adatokból szülessen telepítési döntés.',
    'HashMismatch': 'A firmware tartalma vagy mérete eltér a manifestben rögzítetttől. Az elutasítás megakadályozza a módosított vagy sérült állomány telepítését.',
    'RollbackRejected': 'A csomag verziója nem újabb a telepítettnél. Az elutasítás megakadályozza egy régi, esetleg ismert sérülékenységet tartalmazó verzió visszatelepítését.',
    'ModelMismatch': 'A csomagot más eszközmodellhez készítették. Az elutasítás segít megelőzni a nem kompatibilis firmware telepítését.',
}

GLOSSARY = {
    'privát kulcs': 'A gyártó titkos kulcsa, amellyel aláírja a manifestet. Illetéktelen kézbe kerülése hamis kiadásokat tenne lehetővé.',
    'publikus kulcs': 'Az aláírás ellenőrzéséhez használt, megosztható kulcs. Az eszköznek megbízható forrásból kell ismernie.',
    'aláírás': 'A privát kulccsal készített érték, amelyet a megfelelő publikus kulccsal lehet ellenőrizni. A manifest hitelességét és sértetlenségét védi.',
    'hash (SHA-256)': 'Az SHA-256 egy tetszőleges hosszúságú adatból rögzített hosszúságú lenyomatot számol. Az eltérő lenyomat tartalmi eltérést jelez.',
    'manifest': 'A firmware méretét, hashét és kiadási adatait leíró JSON-objektum. Az aláírás ennek kanonikus változatára vonatkozik.',
    'kanonikus JSON': 'A manifest egységes, rendezett kulcsú, felesleges szóközöket nem tartalmazó JSON-ábrázolása. Ez adja az aláírt bájtokat.',
    'rollback': 'Visszatérés egy korábbi firmware-verzióra. Ez újra előhozhat már javított sérülékenységeket.',
    'bizalmi horgony': 'Az az előre megbízhatónak tekintett adat, például publikus kulcs, amelyre az ellenőrzés épül. Ha kicserélhető, a bizalmi lánc sérül.',
    'Ed25519': 'Digitális aláírási algoritmus az Edwards-görbéken alapuló EdDSA családból. A projekt ezzel írja alá a manifestet.',
    'EdDSA': 'Edwards-görbéket használó digitális aláírási algoritmuscsalád. Az Ed25519 ennek egyik konkrét változata.',
    'nonce': 'Egy adott kulccsal végzett titkosításnál egyszer használatos érték. Az AES-GCM biztonságához kulcsonként nem ismétlődhet.',
    'AEAD': 'Olyan titkosítás, amely a titkosság mellett a titkosított adat hitelességét is védi. Itt az AES-GCM védi a privát kulcsot.',
}
