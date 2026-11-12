
from __future__ import annotations

import hashlib
import html
import shutil
import time
from datetime import date, datetime
from itertools import islice, product
from pathlib import Path
from typing import Any, Callable, Generator

import streamlit as st  # type: ignore
from cryptography.hazmat.primitives import serialization  # type: ignore

from attacks import run_attacks
from device.explanations import EXCEPTION_EXPLANATIONS
from device.state import read_installed_version, write_installed_version
from device.verify import UpdateRejected, verify_with_trace
from signer.keys import (
    generate_keypair,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
)
from signer.sign import create_bundle, write_bundle


st.set_page_config(
    page_title="Aláírt firmware-frissítés",
    page_icon="🔐",
    layout="wide",
)


# ---------------------------------------------------------------------
# Beállítások és útvonalak
# ---------------------------------------------------------------------

APP_DIR = Path(__file__).resolve().parent

KEYS = APP_DIR / "keys"
OUT = APP_DIR / "out"
STATE = APP_DIR / "device" / "device_state.json"
PASSWORD_LIST = APP_DIR / "jelszavak.txt"

DEVICE_MODEL = "demo-device"

# A bemutató lépései legalább öt másodpercig láthatók.
STEP_SECONDS = 10

# Az automatikus próba a teljes jelszavak.txt fájlt vizsgálja.
# Ez a korlát csak az utána következő kiegészítő jelöltekre érvényes.
AUTO_ATTACK_MAX_EXTRA_GUESSES = 120
AUTO_ATTACK_DELAY_SECONDS = 0.015

# A külön feltölthető szólista-audit korlátai.
MAX_WORDLIST_BYTES = 2 * 1024 * 1024
MAX_WORDLIST_GUESSES = 1_000
MAX_BRUTE_FORCE_ATTEMPTS = 300
MAX_BRUTE_FORCE_LENGTH = 8
MAX_ALPHABET_SIZE = 64

MAX_TERMINAL_LINES = 500
MAX_FIRMWARE_BYTES = 64 * 1024 * 1024


COMMON_ATTACK_GUESSES = [
    "1234",
    "123456",
    "password",
    "admin",
    "admin123",
    "demo",
    "demo123",
    "firmware",
    "qwerty",
    "letmein",
    "0000",
    "1111",
    "123",
    "12345",
    "password123",
    "root",
    "guest",
    "welcome",
    "changeme",
    "007",
    "42",
    "test",
    "12345678",
    "pass",
    "000000",
]


ATTACK_SCENARIOS = [
    {
        "title": "Firmware-adatok módosítása",
        "text": (
            "Az engedélyezett biztonsági teszt során módosítanak egy bájtot a firmware-ben; "
            "az újraszámított SHA-256-lenyomat nem egyezik a manifestben rögzített értékkel, "
            "ezért a készülék elutasítja a csomagot."
        ),
    },
    {
        "title": "Verzióadat módosítása",
        "text": (
            "A teszt során átírják a manifest verzióadatát; az aláírás ellenőrzése sikertelen lesz, "
            "ezért a készülék elutasítja a csomagot."
        ),
    },
    {
        "title": "Aláírás idegen kulccsal",
        "text": (
            "A tesztelő idegen privát kulccsal írja alá a csomagot; "
            "a készülék megbízható gyártói publikus kulcsa nem igazolja az aláírást, "
            "ezért a csomagot elutasítja."
        ),
    },
    {
        "title": "Régebbi kiadás visszatelepítése",
        "text": (
            "A tesztelő egy korábban érvényesen aláírt, de a készüléken telepítettnél régebbi "
            "firmware-t próbál telepíteni; a verzió-visszalépés elleni védelem elutasítja."
        ),
    },
    {
        "title": "Aláírás eltávolítása",
        "text": (
            "A tesztelő eltávolítja a digitális aláírást a csomagból; "
            "aláírás nélkül a készülék nem tudja hitelesíteni a kiadást, ezért elutasítja."
        ),
    },
]



VERIFY_EXPLANATIONS = {
    1: {
        "title": "1/5 — Digitális aláírás",
        "what": (
            "Az eszköz a megbízható publikus kulccsal ellenőrzi a manifest aláírását."
        ),
        "why": (
            "Az érvényes aláírás igazolja, hogy az aláírt adatok a megfelelő "
            "privát kulccsal készültek, és azóta nem változtak meg."
        ),
    },
    2: {
        "title": "2/5 — Csomagformátum és mezők",
        "what": (
            "A csomagfeldolgozó ellenőrzi a formátumot és a kötelező manifestmezőket."
        ),
        "why": (
            "Hiányos vagy nem értelmezhető csomagból az eszköz nem tud "
            "megbízható telepítési adatokat kinyerni."
        ),
    },
    3: {
        "title": "3/5 — Célmodell",
        "what": (
            "Az eszköz összeveti a manifest modellazonosítóját a saját modellazonosítójával."
        ),
        "why": (
            "A másik eszközmodellhez vagy termékcsaládhoz készült firmware "
            "nem telepíthető erre az eszközre."
        ),
    },
    4: {
        "title": "4/5 — Firmware mérete és SHA-256-lenyomata",
        "what": (
            "Az eszköz ellenőrzi a firmware bájtméretét, majd újraszámítja "
            "a fájl SHA-256-lenyomatát, és összeveti a manifestben szereplő értékekkel."
        ),
        "why": (
            "A méret- vagy lenyomateltérés sérülésre, fájlcserére "
            "vagy tartalommódosításra utal."
        ),
    },
    5: {
        "title": "5/5 — Verzió és visszalépés",
        "what": (
            "Az eszköz összeveti a csomag verzióját a helyben nyilvántartott "
            "telepített verzióval."
        ),
        "why": (
            "A régebbi verzióra történő visszaállítás visszahozhat már javított "
            "hibákat, ezért azt az eszköz elutasítja."
        ),
    },
}

VERIFY_EXPLANATIONS = {
    1: {
        "title": "1/5 — Gyártói aláírás",
        "what": (
            "Az eszköz ellenőrzi, hogy a csomagot a megbízható gyártói "
            "kulccsal írták-e alá, és az aláírt adatok azóta nem változtak-e meg."
        ),
        "why": (
            "Így az eszköz felismeri az ismeretlen eredetű vagy "
            "utólag módosított csomagot."
        ),
    },
    2: {
        "title": "2/5 — A csomag felépítése",
        "what": (
            "Az eszköz ellenőrzi, hogy a csomag megfelelően van-e összeállítva, "
            "és minden szükséges adat megtalálható-e benne."
        ),
        "why": "A hibás vagy hiányos csomagot nem biztonságos telepíteni.",
    },
    3: {
        "title": "3/5 — A megfelelő eszközmodell",
        "what": (
            "Az eszköz ellenőrzi, hogy a firmware az ő pontos modelljéhez készült-e."
        ),
        "why": "Másik modellhez készült firmware-t nem enged telepíteni.",
    },
    4: {
        "title": "4/5 — A firmware-fájl épsége",
        "what": (
            "Az eszköz összehasonlítja a firmware méretét és digitális "
            "lenyomatát a csomagban megadott értékekkel."
        ),
        "why": (
            "Ha a fájl megsérült vagy módosították, az értékek nem egyeznek, "
            "ezért az eszköz elutasítja."
        ),
    },
    5: {
        "title": "5/5 — A firmware verziója",
        "what": (
            "Az eszköz összehasonlítja a csomag verzióját a jelenleg telepített "
            "verzióval."
        ),
        "why": (
            "Csak újabb verziót enged telepíteni, így nem lehet régebbi "
            "firmware-re visszalépni."
        ),
    },
}
# ---------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------

APP_CSS = """
:root {
    color-scheme: dark;
    --bg: #070b13;
    --panel: #0e1622;
    --panel-2: #111d2b;
    --line: rgba(159, 185, 213, .16);
    --text: #ecf3fb;
    --muted: #98a9bc;
    --cyan: #67e8f9;
    --green: #6ee7b7;
    --red: #fda4af;
    --gold: #fbbf24;
}

html, body, [class*="css"] {
    font-family: Inter, "Segoe UI", system-ui, sans-serif;
}

.stApp {
    color: var(--text);
    background:
        radial-gradient(ellipse at 8% -5%, rgba(22, 129, 160, .18), transparent 36rem),
        radial-gradient(ellipse at 92% 3%, rgba(112, 76, 201, .15), transparent 34rem),
        linear-gradient(180deg, #070b13 0%, #091321 55%, #070c14 100%);
}

[data-testid="stHeader"] {
    background: rgba(7, 11, 19, .78);
}

main .block-container {
    width: 100%;
    max-width: none !important;
    padding: .9rem clamp(1rem, 2vw, 2.2rem) 2rem;
}

[data-testid="stMarkdownContainer"] p {
    color: var(--muted);
    line-height: 1.55;
}

[data-testid="stWidgetLabel"] p {
    color: #dbe7f4 !important;
    font-weight: 650;
}

[data-testid="stForm"] {
    padding: 1rem 1.15rem .8rem;
    border: 1px solid var(--line);
    border-radius: 18px;
    background: linear-gradient(145deg, rgba(16, 29, 44, .94), rgba(10, 18, 29, .94));
    box-shadow: 0 16px 40px rgba(0, 0, 0, .18);
}

[data-testid="stFileUploaderDropzone"] {
    border: 1px dashed rgba(135, 169, 203, .38);
    border-radius: 12px;
    background: rgba(5, 12, 21, .48);
}

.stTextInput input,
.stNumberInput input {
    border-color: rgba(148, 163, 184, .24);
    border-radius: 10px;
    background: rgba(5, 12, 21, .66);
}

.stButton > button,
[data-testid="stFormSubmitButton"] button {
    min-height: 2.7rem;
    border: 1px solid rgba(148, 163, 184, .2);
    border-radius: 11px;
    font-weight: 750;
    transition: transform .16s ease, box-shadow .16s ease, border-color .16s ease;
}

.stButton > button:hover,
[data-testid="stFormSubmitButton"] button:hover {
    transform: translateY(-1px);
    border-color: rgba(103, 232, 249, .55);
    box-shadow: 0 8px 22px rgba(0, 0, 0, .22);
}

[data-testid="stFormSubmitButton"] button[kind="primary"],
.stButton > button[kind="primary"],
.stButton > button[data-testid="stBaseButton-primary"] {
    border: 0;
    background: linear-gradient(100deg, #67e8f9, #a5b4fc);
    color: #07111b;
}

/* Fejléc */

.hero {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 24px;
    margin-bottom: 1rem;
    padding: clamp(1.2rem, 2.4vw, 2rem);
    border: 1px solid rgba(142, 181, 215, .19);
    border-radius: 22px;
    background:
        radial-gradient(circle at 82% 14%, rgba(103, 232, 249, .12), transparent 24rem),
        linear-gradient(120deg, rgba(17, 34, 52, .98), rgba(8, 17, 28, .98));
    box-shadow: 0 18px 55px rgba(0, 0, 0, .22);
}

.hero-copy {
    min-width: 0;
}

.hero-kicker,
.section-kicker {
    color: #91a9c0;
    font-size: 10px;
    font-weight: 850;
    letter-spacing: .16em;
    text-transform: uppercase;
}

.hero h1 {
    margin: .45rem 0 .35rem;
    color: #f4f8ff;
    font-size: clamp(2rem, 4vw, 3.2rem);
    font-weight: 850;
    letter-spacing: -.055em;
    line-height: 1.04;
}

.hero p {
    max-width: 760px;
    margin: 0;
    color: #b0c0d2;
    font-size: 14px;
}

.hero-side {
    flex: 0 0 auto;
    display: grid;
    gap: 9px;
    min-width: 190px;
    padding: 13px 15px;
    border: 1px solid rgba(103, 232, 249, .18);
    border-radius: 14px;
    background: rgba(5, 14, 23, .55);
}

.hero-chip {
    display: flex;
    align-items: center;
    gap: 8px;
    color: #d5e1ed;
    font-size: 10px;
    font-weight: 750;
    letter-spacing: .04em;
}

.hero-chip-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #6ee7b7;
    box-shadow: 0 0 12px rgba(110, 231, 183, .75);
}

/* Panelek és címek */

.section-heading {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 12px;
    margin: .3rem 0 .65rem;
}

.section-heading h2 {
    margin: 0;
    color: #eaf2fa;
    font-size: 16px;
    font-weight: 800;
}

.section-hint {
    color: #8194a8;
    font-size: 10px;
}

.panel-heading {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    margin: .3rem 0 .65rem;
}

.panel-heading strong {
    color: #e6eef7;
    font-size: 14px;
    font-weight: 800;
}

.panel-live {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: #75e4bc;
    font-size: 9px;
    font-weight: 800;
    letter-spacing: .1em;
}

.panel-live::before {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #34d399;
    box-shadow: 0 0 10px rgba(52, 211, 153, .8);
    content: "";
}

/* Animált jelenet */

.storyboard {
    margin: .35rem 0 .7rem;
    padding: clamp(.9rem, 1.5vw, 1.3rem);
    border: 1px solid rgba(103, 232, 249, .25);
    border-radius: 18px;
    background:
        radial-gradient(circle at 5% 0%, rgba(34, 211, 238, .085), transparent 26rem),
        linear-gradient(145deg, rgba(14, 27, 42, .98), rgba(7, 14, 23, .98));
    box-shadow: 0 16px 42px rgba(0, 0, 0, .23);
}

.storyboard.stage-attacker,
.storyboard.stage-bruteforce,
.storyboard.stage-bruteforce-success {
    border-color: rgba(251, 113, 133, .42);
    background:
        radial-gradient(circle at 90% 0%, rgba(251, 113, 133, .09), transparent 24rem),
        linear-gradient(145deg, #17131d, #0a1019);
}

.storyboard.stage-done {
    border-color: rgba(52, 211, 153, .4);
}

.storyboard.stage-error {
    border-color: rgba(251, 113, 133, .5);
}

.network-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 11px;
}

.network-kicker {
    color: #91a8bd;
    font-size: 9px;
    font-weight: 850;
    letter-spacing: .15em;
}

.network-title {
    margin-top: 4px;
    color: #f2f7ff;
    font-size: clamp(17px, 1.55vw, 23px);
    font-weight: 820;
    line-height: 1.2;
}

.network-status {
    flex: 0 0 auto;
    padding: 6px 9px;
    border: 1px solid rgba(103, 232, 249, .3);
    border-radius: 20px;
    background: rgba(103, 232, 249, .075);
    color: #a5f3fc;
    font-size: 8px;
    font-weight: 850;
    letter-spacing: .08em;
}

.stage-attacker .network-status,
.stage-bruteforce .network-status,
.stage-bruteforce-success .network-status,
.stage-bruteforce-failed .network-status {
    border-color: rgba(251, 113, 133, .4);
    background: rgba(251, 113, 133, .08);
    color: #fda4af;
}

.network-scene {
    position: relative;
    height: clamp(230px, 31vh, 350px);
    overflow: hidden;
    border: 1px solid rgba(103, 232, 249, .18);
    border-radius: 15px;
    background:
        radial-gradient(circle at 50% 48%, rgba(34, 211, 238, .11), transparent 36%),
        linear-gradient(135deg, #091421, #101d2d);
}

.network-scene::before {
    position: absolute;
    inset: 0;
    background-image: radial-gradient(rgba(148, 163, 184, .17) .7px, transparent .7px);
    background-size: 20px 20px;
    opacity: .18;
    content: "";
    pointer-events: none;
}

.network-route {
    position: absolute;
    z-index: 1;
    top: 50%;
    right: 12%;
    left: 12%;
    height: 2px;
    background: repeating-linear-gradient(
        90deg,
        rgba(103, 232, 249, .6) 0 8px,
        transparent 8px 15px
    );
    animation: route-flow 1.2s linear infinite;
}

.scene-node {
    position: absolute;
    z-index: 2;
    top: 50%;
    display: grid;
    width: 22%;
    min-width: 86px;
    min-height: 104px;
    align-content: center;
    justify-items: center;
    gap: 5px;
    padding: 8px 5px;
    transform: translateY(-50%);
    border: 1px solid rgba(148, 163, 184, .2);
    border-radius: 14px;
    background: rgba(13, 25, 39, .96);
    color: #b5c2d0;
    opacity: .58;
    text-align: center;
    transition: border-color .25s ease, opacity .25s ease, box-shadow .25s ease;
}

.scene-node.factory {
    left: 2.5%;
}

.scene-node.cloud {
    left: 39%;
}

.scene-node.device {
    right: 2.5%;
}

.scene-node.active {
    border-color: rgba(103, 232, 249, .68);
    background: rgba(17, 37, 55, .98);
    color: #f3f7ff;
    opacity: 1;
    box-shadow: 0 0 22px rgba(103, 232, 249, .08);
}

.scene-node.cloud.active {
    border-color: rgba(167, 139, 250, .7);
    box-shadow: 0 0 24px rgba(167, 139, 250, .1);
}

.scene-node.device.active {
    border-color: rgba(52, 211, 153, .6);
    box-shadow: 0 0 24px rgba(52, 211, 153, .1);
}

.scene-icon {
    font-size: 30px;
    line-height: 1;
}

.scene-node strong {
    color: #eef5fb;
    font-size: 10px;
    font-weight: 850;
    letter-spacing: .06em;
}

.scene-node small {
    color: #9bacc0;
    font-size: 9px;
}

.node-badge {
    position: absolute;
    top: 5px;
    right: 5px;
    display: none;
    place-items: center;
    width: 22px;
    height: 22px;
    border: 1px solid rgba(148, 163, 184, .18);
    border-radius: 50%;
    background: #102638;
    font-size: 13px;
}

.stage-checking .node-badge.shield,
.stage-attacker .node-badge.shield {
    display: grid;
}

.stage-accepted .node-badge.accepted,
.stage-bruteforce-success .node-badge.breached {
    display: grid;
}

.moving-package,
.attack-packet {
    position: absolute;
    z-index: 5;
    display: none;
    place-items: center;
    width: 38px;
    height: 38px;
    border: 1px solid rgba(103, 232, 249, .68);
    border-radius: 11px;
    background: #10263b;
    box-shadow: 0 0 20px rgba(103, 232, 249, .2);
    font-size: 20px;
}

.stage-delivery .moving-package {
    top: calc(50% - 19px);
    left: calc(13% - 19px);
    display: grid;
    animation: package-ready .8s ease-in-out infinite alternate;
}

.stage-uploading .moving-package {
    top: calc(50% - 19px);
    display: grid;
    animation: send-to-cloud 2.4s ease-in-out infinite;
}

.stage-downloading .moving-package {
    top: calc(50% - 19px);
    display: grid;
    animation: send-to-device 2.4s ease-in-out infinite;
}

.stage-checking .moving-package,
.stage-accepted .moving-package {
    top: calc(50% - 19px);
    left: calc(86% - 19px);
    display: grid;
}

.signature-stamp {
    position: absolute;
    z-index: 5;
    top: 7%;
    left: 7%;
    display: none;
    padding: 7px 9px;
    border: 1px solid rgba(103, 232, 249, .42);
    border-radius: 9px;
    background: #10253a;
    color: #a5f3fc;
    font-size: 9px;
    font-weight: 850;
    letter-spacing: .05em;
}

.stage-signing .signature-stamp {
    display: flex;
    animation: stamp-pop .7s ease-in-out infinite alternate;
}

.stage-checking .scene-node.device::after {
    position: absolute;
    z-index: 4;
    top: 0;
    bottom: 0;
    left: -5px;
    width: 5px;
    border-radius: 5px;
    background: #67e8f9;
    box-shadow: 0 0 18px #67e8f9;
    content: "";
    animation: scan-device 1.3s linear infinite;
}

.attacker-figure {
    position: absolute;
    z-index: 4;
    top: 78%;
    left: 41%;
    display: none;
    align-items: center;
    gap: 6px;
    padding: 6px 9px;
    border: 1px solid rgba(251, 113, 133, .4);
    border-radius: 10px;
    background: #25151f;
    color: #fda4af;
    font-size: 9px;
    font-weight: 850;
}

.stage-attacker .attacker-figure,
.stage-bruteforce .attacker-figure,
.stage-bruteforce-success .attacker-figure,
.stage-bruteforce-failed .attacker-figure {
    display: flex;
    animation: attacker-pulse .7s ease-in-out infinite alternate;
}

.stage-attacker .attack-packet,
.stage-bruteforce .attack-packet {
    display: grid;
    border-color: rgba(251, 113, 133, .78);
    background: #321822;
    box-shadow: 0 0 20px rgba(251, 113, 133, .22);
}

.stage-attacker .attack-packet {
    animation: attack-flight 1.8s ease-in-out infinite;
}

.stage-bruteforce .attack-packet {
    animation: key-flight 1.4s ease-in-out infinite;
}

.stage-uploading .scene-node.factory,
.stage-uploading .scene-node.cloud,
.stage-downloading .scene-node.cloud,
.stage-downloading .scene-node.device,
.stage-checking .scene-node.device {
    animation: node-glow 1s ease-in-out infinite alternate;
}

.stage-attacker .scene-node.device {
    border-color: rgba(52, 211, 153, .58);
}

.stage-bruteforce .scene-node.device {
    border-color: rgba(251, 113, 133, .58);
}

.scene-caption {
    margin-top: 10px;
    padding: 11px 13px;
    border: 1px solid rgba(148, 163, 184, .14);
    border-radius: 12px;
    background: rgba(255, 255, 255, .025);
}

.scene-action-label {
    color: #8da3b9;
    font-size: 9px;
    font-weight: 850;
    letter-spacing: .12em;
}

.scene-action {
    margin-top: 5px;
    color: #eef5fc;
    font-size: clamp(14px, 1.2vw, 17px);
    font-weight: 720;
    line-height: 1.5;
    overflow-wrap: anywhere;
}

.scene-importance {
    margin-top: 7px;
    color: #86efac;
    font-size: 12px;
    font-weight: 680;
    line-height: 1.45;
}

.scene-outcome {
    margin-top: 9px;
    padding: 8px 10px;
    border-left: 3px solid;
    border-radius: 7px;
    font-size: 11px;
    line-height: 1.45;
}

.scene-outcome.good {
    border-color: #34d399;
    background: rgba(52, 211, 153, .07);
    color: #a7f3d0;
}

.scene-outcome.bad {
    border-color: #fb7185;
    background: rgba(251, 113, 133, .07);
    color: #fecdd3;
}

/* Jelszópróba */

.live-guess {
    margin: 8px 0 14px;
    padding: 11px 13px;
    border: 1px solid rgba(251, 113, 133, .35);
    border-radius: 12px;
    background: rgba(48, 19, 29, .76);
}

.live-guess-label {
    color: #fda4af;
    font-size: 9px;
    font-weight: 850;
    letter-spacing: .12em;
}

.live-guess-row {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 12px;
    margin-top: 4px;
}

.live-guess-value {
    color: #fff1f2;
    font-size: 21px;
    font-weight: 850;
    overflow-wrap: anywhere;
}

.live-guess-count {
    flex: 0 0 auto;
    color: #cbd5e1;
    font: 10px ui-monospace, Consolas, monospace;
}

.guess-progress {
    height: 5px;
    margin-top: 8px;
    overflow: hidden;
    border-radius: 10px;
    background: rgba(255, 255, 255, .1);
}

.guess-progress span {
    display: block;
    height: 100%;
    border-radius: inherit;
    background: linear-gradient(90deg, #fb7185, #fbbf24);
    transition: width .12s linear;
}

/* Mindig látható, görgethető technikai napló */

.terminal-window {
    display: flex;
    flex-direction: column;
    height: clamp(430px, calc(100vh - 340px), 720px);
    overflow: hidden;
    border: 1px solid rgba(110, 231, 183, .23);
    border-radius: 15px;
    background: #050a10;
    box-shadow: 0 16px 42px rgba(0, 0, 0, .25);
}

.terminal-topbar {
    flex: 0 0 auto;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 11px 13px;
    border-bottom: 1px solid rgba(148, 163, 184, .14);
    background: #0c151d;
    color: #a6b8c8;
    font: 800 9px/1.2 ui-monospace, Consolas, monospace;
    letter-spacing: .08em;
}

.terminal-dots {
    display: flex;
    gap: 5px;
}

.terminal-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
}

.terminal-red { background: #fb7185; }
.terminal-yellow { background: #fbbf24; }
.terminal-green-dot { background: #34d399; }

.terminal-body {
    display: flex;
    flex: 1;
    min-height: 0;
    flex-direction: column-reverse;
    overflow-y: auto;
    padding: 10px 12px;
    color: #cbd5e1;
    font: 10px/1.65 ui-monospace, Consolas, monospace;
    scrollbar-color: #314356 #080e15;
}

.terminal-line {
    display: block;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
}

.log-normal { color: #cbd5e1; }
.log-ok { color: #6ee7b7; }
.log-warn { color: #fbbf24; }
.log-error { color: #fda4af; }
.log-attack { color: #fb7185; }

/* Kiegészítő panelek */

[data-testid="stExpander"] {
    border: 1px solid rgba(148, 163, 184, .17);
    border-radius: 13px;
    background: rgba(255, 255, 255, .025);
}

.footer-note {
    margin-top: 1.3rem;
    padding-top: .8rem;
    border-top: 1px solid rgba(148, 163, 184, .12);
    color: #71839b;
    font-size: 9px;
    letter-spacing: .09em;
    text-align: center;
}

/* Animációk */

@keyframes send-to-cloud {
    0%   { left: 13%; opacity: 0; transform: scale(.75); }
    12%  { opacity: 1; transform: scale(1); }
    70%  { left: 49%; opacity: 1; }
    86%  { left: 49%; opacity: 0; }
    100% { left: 13%; opacity: 0; }
}

@keyframes send-to-device {
    0%   { left: 49%; opacity: 0; transform: scale(.75); }
    12%  { opacity: 1; transform: scale(1); }
    70%  { left: 85%; opacity: 1; }
    86%  { left: 85%; opacity: 0; }
    100% { left: 49%; opacity: 0; }
}

@keyframes attack-flight {
    0%   { left: 50%; top: 76%; opacity: 0; transform: scale(.7); }
    12%  { opacity: 1; transform: scale(1); }
    72%  { left: 80%; top: 47%; opacity: 1; }
    86%  { left: 80%; top: 47%; opacity: 0; transform: scale(.6); }
    100% { left: 50%; top: 76%; opacity: 0; }
}

@keyframes key-flight {
    0%   { left: 45%; top: 75%; opacity: 0; transform: scale(.7); }
    15%  { opacity: 1; transform: scale(1); }
    72%  { left: 80%; top: 49%; opacity: 1; }
    88%  { left: 80%; top: 49%; opacity: 0; transform: scale(.7); }
    100% { left: 45%; top: 75%; opacity: 0; }
}

@keyframes scan-device {
    from { left: -5px; }
    to   { left: calc(100% + 5px); }
}

@keyframes node-glow {
    from { box-shadow: 0 0 0 rgba(103, 232, 249, 0); }
    to   { box-shadow: 0 0 20px rgba(103, 232, 249, .22); }
}

@keyframes package-ready {
    from { transform: scale(.9); }
    to   { transform: scale(1.08); }
}

@keyframes stamp-pop {
    from { transform: scale(.88); }
    to   { transform: scale(1.05); }
}

@keyframes attacker-pulse {
    from { opacity: .65; }
    to   { opacity: 1; }
}

@keyframes route-flow {
    to { background-position: 15px 0; }
}

@media (max-width: 900px) {
    .hero {
        align-items: flex-start;
    }

    .hero-side {
        min-width: 155px;
    }

    .terminal-window {
        height: 480px;
    }
}

@media (max-width: 650px) {
    main .block-container {
        padding: .8rem .7rem 1.5rem;
    }

    .hero {
        flex-direction: column;
        padding: 1.2rem;
    }

    .hero-side {
        width: 100%;
    }

    .network-scene {
        height: 225px;
    }

    .scene-node {
        width: 24%;
        min-width: 70px;
        min-height: 86px;
        padding: 5px 3px;
    }

    .scene-node strong {
        font-size: 8px;
    }

    .scene-node small {
        font-size: 8px;
    }

    .scene-icon {
        font-size: 24px;
    }

    .terminal-window {
        height: 370px;
    }
}

@media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
        animation-duration: .01ms !important;
        transition-duration: .01ms !important;
    }
}
"""


def inject_css() -> None:
    st.markdown(f"<style>{APP_CSS}</style>", unsafe_allow_html=True)


def safe_text(value: Any) -> str:
    """HTML-biztos szöveg; a sortöréseket HTML-sortöréssé alakítja."""
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    return html.escape(text).replace("\n", "<br>")


def plain_text(value: Any, default: str = "", limit: int = 260) -> str:
    if value is None:
        value = default
    text = " ".join(str(value).split())
    return text[:limit].strip()


def ensure_period(text: str) -> str:
    text = text.strip()
    if text and not text.endswith((".", "!", "?", "…")):
        text += "."
    return text


def add_hungarian_article(actor: str) -> str:
    actor = " ".join(actor.split())
    if not actor:
        return ""

    first_word = actor.split(maxsplit=1)[0].casefold()
    if first_word in {"a", "az", "egy"}:
        return actor

    first_letter = next(
        (character for character in actor if character.isalpha()),
        "",
    )
    vowels = "aáeéiíoóöőuúüű"
    article = "Az" if first_letter.casefold() in vowels else "A"

    actor = actor[:1].lower() + actor[1:]
    return f"{article} {actor}"


def highlight_phrases(
    text: str,
    phrases: list[tuple[str, str]],
) -> str:
    """A mondatban szereplő szereplőt és helyet színezi ki."""
    folded_text = text.casefold()
    ranges: list[tuple[int, int, str]] = []

    for phrase, style in phrases:
        phrase = phrase.strip()
        if not phrase:
            continue

        start = folded_text.find(phrase.casefold())
        if start < 0:
            continue

        end = start + len(phrase)
        if end <= len(text):
            ranges.append((start, end, style))

    # Átfedésnél az elsőként kezdődő, hosszabb kifejezés élvez elsőbbséget.
    ranges.sort(key=lambda item: (item[0], -(item[1] - item[0])))

    parts: list[str] = []
    cursor = 0

    for start, end, style in ranges:
        if start < cursor:
            continue

        parts.append(html.escape(text[cursor:start]))
        parts.append(
            f'<span style="{style}">{html.escape(text[start:end])}</span>'
        )
        cursor = end

    parts.append(html.escape(text[cursor:]))
    return "".join(parts)


def draw_story(placeholder, story: dict[str, Any]) -> None:
    """Megjeleníti az animált gyártó → internet → eszköz jelenetet."""

    allowed_stages = {
        "idle",
        "factory",
        "keys",
        "signing",
        "delivery",
        "uploading",
        "downloading",
        "checking",
        "accepted",
        "attacker",
        "bruteforce",
        "bruteforce-success",
        "bruteforce-failed",
        "done",
        "error",
    }

    if not isinstance(story, dict):
        story = {}

    stage = story.get("stage", "idle")
    if not isinstance(stage, str) or stage not in allowed_stages:
        stage = "idle"

    statuses = {
        "idle": "VÁRAKOZIK",
        "factory": "FÁJL BEOLVASÁSA",
        "keys": "KULCS ELŐKÉSZÍTÉSE",
        "signing": "ALÁÍRÁS",
        "delivery": "CSOMAG MENTÉSE",
        "uploading": "CSOMAGÚTVONAL",
        "downloading": "LETÖLTÉSI ÚTVONAL",
        "checking": "ELLENŐRZÉS",
        "accepted": "ELFOGADVA",
        "attacker": "TÁMADÁSPRÓBA",
        "bruteforce": "JELSZÓPRÓBA",
        "bruteforce-success": "TALÁLAT",
        "bruteforce-failed": "PRÓBA KÉSZ",
        "done": "BEMUTATÓ KÉSZ",
        "error": "HIBA",
    }

    default_actions = {
        "idle": "Add meg az elkészült firmware-binárist és az aláírókulcs jelszavát.",
        "factory": (
            "A kiadási folyamat kész firmware-binárist ad át; "
            "az alkalmazás a fájl bájtjait olvassa be."
        ),
        "keys": (
            "A kiadási rendszer előkészíti a privát aláírókulcsot "
            "és a hozzá tartozó publikus kulcsot."
        ),
        "signing": (
            "A csomagkészítő manifestet állít elő, lenyomatot számít, "
            "majd aláírja a manifestet."
        ),
        "delivery": (
            "Az alkalmazás az aláírt csomagot az out/ mappába menti."
        ),
        "uploading": (
            "Üzemi rendszerben a kiadási szolgáltatás a verziózott csomagot "
            "HTTPS-en publikálja a frissítési tárhelyen; ez a program nem küld HTTP-kérést."
        ),
        "downloading": (
            "Üzemi rendszerben az eszköz frissítési kliense a neki szánt csomagot "
            "HTTPS-en tölti le; ez a program nem végez hálózati letöltést."
        ),
        "checking": (
            "Az ellenőrző a csomag aláírását, felépítését, célmodelljét, "
            "fájladatait és verzióját vizsgálja."
        ),
        "accepted": (
            "Az ellenőrzés sikeres; a demó az eszköz helyi verzióállapotát frissíti."
        ),
        "attacker": (
            "A tesztcsomagok módosításait az eszköz ellenőrzési eljárása vizsgálja."
        ),
        "bruteforce": (
            "A jelszópróba kizárólag a helyi keys/private.json fájlt vizsgálja."
        ),
        "bruteforce-success": (
            "A megpróbált jelölt megnyitotta a helyi privát kulcsot."
        ),
        "bruteforce-failed": (
            "A kipróbált jelöltek egyike sem nyitotta meg a helyi privát kulcsot."
        ),
        "done": "A bemutató összesíti az ellenőrzési eredményeket.",
        "error": "A folyamat hiba miatt leállt.",
    }


    factory_active = stage in {
        "factory",
        "keys",
        "signing",
        "delivery",
        "uploading",
    }
    cloud_active = stage in {"uploading", "downloading", "attacker"}
    device_active = stage in {
        "downloading",
        "checking",
        "accepted",
        "attacker",
        "bruteforce",
        "bruteforce-success",
        "bruteforce-failed",
        "done",
    }

    is_bruteforce = stage.startswith("bruteforce")
    target_icon = "🔐" if is_bruteforce else "📟"
    target_title = "PRIVÁT KULCS" if is_bruteforce else "ESZKÖZ"
    target_caption = (
        "jelszóval védett" if is_bruteforce else "letölt · ellenőriz"
    )

    raw_action = story.get("what")
    has_custom_action = raw_action is not None and bool(str(raw_action).strip())
    action = plain_text(raw_action, default_actions[stage], limit=1200) or default_actions[stage]

    who = plain_text(story.get("who"), "", 60)
    where = plain_text(story.get("where"), "", 80)
    actor_to_highlight = who

    # A szereplő az eseménymondat alanya lesz; külön KI? mező nem jelenik meg.
    if (
        who
        and has_custom_action
        and stage != "idle"
        and who.casefold() not in action.casefold()
    ):
        actor_to_highlight = add_hungarian_article(who)
        action = f"{actor_to_highlight} {action[:1].lower()}{action[1:]}"

    action = ensure_period(action)

    if stage == "attacker" or is_bruteforce or who.casefold() == "támadó":
        actor_style = "color:#fda4af;font-weight:850;"
    elif who.casefold() in {"eszköz", "device"}:
        actor_style = "color:#6ee7b7;font-weight:850;"
    else:
        actor_style = "color:#67e8f9;font-weight:850;"

    location_style = "color:#fbbf24;font-weight:850;"
    defense_style = "color:#6ee7b7;font-weight:850;"

    phrases = [
        (actor_to_highlight, actor_style),
        (where, location_style),
    ]
    if stage == "attacker":
        phrases.append(("az eszköz", defense_style))

    action_markup = highlight_phrases(action, phrases)

    title = plain_text(story.get("title"), "Firmware-frissítés", 100)

    def node(
        kind: str,
        icon: str,
        node_title: str,
        caption: str,
        active: bool,
        extra: str = "",
    ) -> str:
        active_class = " active" if active else ""
        return (
            f'<div class="scene-node {kind}{active_class}">'
            f'<span class="scene-icon">{html.escape(icon)}</span>'
            f"<strong>{html.escape(node_title)}</strong>"
            f"<small>{html.escape(caption)}</small>"
            f"{extra}"
            "</div>"
        )

    device_badges = (
        '<span class="node-badge shield">🛡️</span>'
        '<span class="node-badge accepted">✓</span>'
        '<span class="node-badge breached">⚠️</span>'
    )

    outcome_markup = ""
    outcome = story.get("outcome")
    if outcome:
        outcome_class = "good" if bool(story.get("outcome_ok", True)) else "bad"
        outcome_markup = (
            f'<div class="scene-outcome {outcome_class}">'
            f'{html.escape(plain_text(outcome, "", 180))}'
            "</div>"
        )

    why_markup = ""
    why = plain_text(story.get("why"), "", limit=700)
    if why:
        why_markup = (
            '<div class="scene-importance">'
            f"{html.escape(ensure_period(why))}"
            "</div>"
        )

    packet_icon = "🔑" if is_bruteforce else "⚠️"

    markup = (
        f'<div class="storyboard stage-{stage}">'
        '<div class="network-header">'
        "<div>"
        '<div class="network-kicker">A FRISSÍTÉS ÚTJA</div>'
        f'<div class="network-title">{html.escape(title)}</div>'
        "</div>"
        f'<div class="network-status">{statuses[stage]}</div>'
        "</div>"

        '<div class="network-scene">'
        '<div class="network-route"></div>'
        f'{node("factory", "🏭", "GYÁRTÓ", "készít · aláír", factory_active)}'
        f'{node("cloud", "☁️", "INTERNET", "frissítési szerver", cloud_active)}'
        f'{node("device", target_icon, target_title, target_caption, device_active, device_badges)}'
        '<div class="signature-stamp">🔏 ALÁÍRVA</div>'
        '<div class="moving-package">📦</div>'
        '<div class="attacker-figure"><span>🕵️</span><span>TÁMADÓ</span></div>'
        f'<div class="attack-packet">{packet_icon}</div>'
        "</div>"

        '<div class="scene-caption">'
        '<div class="scene-action-label">TECHNIKAI MŰVELET</div>'
        f'<div class="scene-action">{action_markup}</div>'
        f"{why_markup}"
        f"{outcome_markup}"
        "</div>"
        "</div>"
    )

    placeholder.markdown(markup, unsafe_allow_html=True)


# ---------------------------------------------------------------------
# Technikai terminálnapló
# ---------------------------------------------------------------------

class Terminal:
    """A technikai eseményeket a jelenet mellett, külön panelben mutatja."""

    def __init__(self, placeholder):
        self.placeholder = placeholder
        saved = st.session_state.get("terminal_lines")

        if isinstance(saved, list):
            self.lines = list(saved)
        else:
            self.lines = ["[INFO] A napló készen áll."]
            st.session_state["terminal_lines"] = self.lines

        self.draw()

    def clear(self) -> None:
        self.lines = []
        st.session_state["terminal_lines"] = self.lines
        self.draw()

    def write(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        text = str(message).replace("\r\n", "\n").replace("\r", "\n")

        for line in text.split("\n"):
            self.lines.append(f"{timestamp}  {line}")

        self.lines = self.lines[-MAX_TERMINAL_LINES:]
        st.session_state["terminal_lines"] = self.lines
        self.draw()

    def draw(self) -> None:
        rendered = []

        # A CSS oszlopirányával együtt a legújabb sor a panel alján marad.
        for line in reversed(self.lines):
            if "[HIBA]" in line or "[FAIL]" in line:
                css_class = "log-error"
            elif "[TÁMADÓ]" in line or "[AUDIT]" in line:
                css_class = "log-attack"
            elif "[FIGYELEM]" in line or "[WARN]" in line:
                css_class = "log-warn"
            elif any(tag in line for tag in ("[OK]", "[KÉSZ]", "[TALÁLAT]")):
                css_class = "log-ok"
            else:
                css_class = "log-normal"

            rendered.append(
                f'<div class="terminal-line {css_class}">'
                f"{html.escape(line)}"
                "</div>"
            )

        if not rendered:
            rendered.append(
                '<div class="terminal-line log-normal">A napló üres.</div>'
            )

        markup = (
            '<div class="terminal-window">'
            '<div class="terminal-topbar">'
            '<span class="terminal-dots">'
            '<span class="terminal-dot terminal-red"></span>'
            '<span class="terminal-dot terminal-yellow"></span>'
            '<span class="terminal-dot terminal-green-dot"></span>'
            "</span>"
            "<span>RÉSZLETES TECHNIKAI NAPLÓ</span>"
            "</div>"
            f'<div class="terminal-body">{"".join(rendered)}</div>'
            "</div>"
        )

        self.placeholder.markdown(markup, unsafe_allow_html=True)


# ---------------------------------------------------------------------
# Kulcsok és ellenőrzési napló
# ---------------------------------------------------------------------

def ensure_keys(password: str, log: Callable[[str], None]):
    """Betölti a meglévő aláírókulcsot, vagy létrehoz egy új kulcspárt."""

    private_path = KEYS / "private.json"

    if private_path.exists() and not private_path.is_file():
        raise ValueError("A keys/private.json útvonal nem fájl.")

    created = not private_path.is_file()

    if created:
        log("[INFO] Új aláírókulcs-pár készül.")
        KEYS.mkdir(parents=True, exist_ok=True)

        private_key, public_key = generate_keypair()
        save_private_key(
            private_key,
            private_path,
            password.encode("utf-8"),
        )
        log("[OK] A jelszóval védett privát kulcs elmentve.")
    else:
        log("[INFO] Meglévő aláírókulcs betöltése.")
        try:
            private_key = load_private_key(
                private_path,
                password.encode("utf-8"),
            )
        except ValueError as exc:
            log("[HIBA] A meglévő kulcsot nem sikerült megnyitni.")
            raise ValueError(
                "A jelszó nem egyezik a meglévő kulcs jelszavával. "
                "Add meg a korábbit, vagy nullázd a kulcsokat."
            ) from exc

        public_key = private_key.public_key()
        log("[OK] A meglévő privát kulcs megnyílt.")

    save_public_key(public_key, KEYS / "public.hex")

    raw_public_key = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    fingerprint = hashlib.sha256(raw_public_key).hexdigest()[:16]

    log(f"[INFO] Gyártói kulcsazonosító: {fingerprint}")
    return private_key, fingerprint, created


def log_trace(trace, log: Callable[[str], None]) -> None:
    """Az öt eszközellenőrzés részletes eredményét naplózza."""

    if not trace:
        log("[FIGYELEM] Nem érkezett ellenőrzési nyomvonal.")
        return

    for step in trace:
        result = "rendben" if step.passed else "sikertelen"
        log(f"[ELLENŐRZÉS] {step.index}/5 — {step.name}: {result}.")
        log(f"[INFO] Elvárt: {step.expected}.")
        log(f"[INFO] Kapott: {step.actual}.")


def get_field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


# ---------------------------------------------------------------------
# Automatikus jelszópróba
# ---------------------------------------------------------------------

def automatic_guess_stream() -> Generator[str, None, None]:
    """Gyakori jelölteket, majd rövid számkombinációkat állít elő."""

    seen: set[str] = set()

    for candidate in COMMON_ATTACK_GUESSES:
        if candidate not in seen:
            seen.add(candidate)
            yield candidate

    for length in range(1, 4):
        for characters in product("0123456789", repeat=length):
            candidate = "".join(characters)
            if candidate not in seen:
                seen.add(candidate)
                yield candidate


def run_automatic_password_attack(
    log: Callable[[str], None],
    show_guess: Callable[..., None],
    wordlist_path: Path | str | None = None,
) -> dict[str, Any]:
    """A jelszavak.txt-t és a korlátozott kiegészítő listát a helyi kulcson próbálja."""

    private_path = KEYS / "private.json"

    if not private_path.is_file():
        log("[FIGYELEM] Nincs helyi privát kulcs; a jelszópróba kimarad.")
        return {
            "found": False,
            "skipped": True,
            "attempts": 0,
            "password": None,
            "wordlist_attempts": 0,
            "extra_attempts": 0,
        }

    path = PASSWORD_LIST if wordlist_path is None else Path(wordlist_path)
    wordlist_count = 0

    if path.is_file():
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as file:
                wordlist_count = sum(
                    1
                    for line in file
                    if line.rstrip("\r\n") != ""
                )
        except (OSError, UnicodeError) as exc:
            log(f"[FIGYELEM] A jelszavak.txt nem olvasható: {exc}")
    else:
        log(f"[FIGYELEM] Nem található a jelszólista: {path}")

    extra_guesses = list(
        islice(
            automatic_guess_stream(),
            AUTO_ATTACK_MAX_EXTRA_GUESSES,
        )
    )
    total = wordlist_count + len(extra_guesses)

    if total == 0:
        log("[FIGYELEM] Nincs kipróbálható jelszójelölt.")
        return {
            "found": False,
            "skipped": True,
            "attempts": 0,
            "password": None,
            "wordlist_attempts": 0,
            "extra_attempts": 0,
        }

    log(
        f"[INFO] Helyi kulcspróba: {wordlist_count} szólista-jelölt, "
        f"legfeljebb {len(extra_guesses)} kiegészítő jelölt."
    )

    started = time.perf_counter()
    attempts = 0
    wordlist_attempts = 0
    extra_attempts = 0

    def try_candidate(candidate: str, phase: str) -> bool:
        nonlocal attempts

        attempts += 1
        show_guess(candidate, attempts, total, phase)

        try:
            private_key = load_private_key(
                private_path,
                candidate.encode("utf-8"),
            )
        except ValueError:
            if attempts == 1 or attempts % 25 == 0:
                log(
                    f"[TÁMADÓ] {attempts}/{total} — "
                    f"helyi kulcsjelölt: {candidate!r}"
                )
            return False

        del private_key
        return True

    if path.is_file() and wordlist_count:
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as file:
                for line in file:
                    candidate = line.rstrip("\r\n")
                    if candidate == "":
                        continue

                    wordlist_attempts += 1

                    if try_candidate(candidate, "Szólista-próba"):
                        elapsed = time.perf_counter() - started
                        log(f"[TALÁLAT] A helyi kulcs jelszava: {candidate!r}")
                        return {
                            "found": True,
                            "skipped": False,
                            "attempts": attempts,
                            "password": candidate,
                            "wordlist_attempts": wordlist_attempts,
                            "extra_attempts": 0,
                            "seconds": elapsed,
                        }
        except (OSError, UnicodeError) as exc:
            log(f"[FIGYELEM] A szólista beolvasása megszakadt: {exc}")

    log(
        f"[INFO] A szólista próbája befejeződött: "
        f"{wordlist_attempts} jelölt."
    )

    for candidate in extra_guesses:
        extra_attempts += 1

        if try_candidate(candidate, "Kiegészítő jelszópróba"):
            elapsed = time.perf_counter() - started
            log(f"[TALÁLAT] A helyi kulcs jelszava: {candidate!r}")
            return {
                "found": True,
                "skipped": False,
                "attempts": attempts,
                "password": candidate,
                "wordlist_attempts": wordlist_attempts,
                "extra_attempts": extra_attempts,
                "seconds": elapsed,
            }

    elapsed = time.perf_counter() - started
    log(
        f"[INFO] Nem volt találat a {wordlist_attempts} szólista- "
        f"és {extra_attempts} kiegészítő jelölt között."
    )
    log(
        "[FIGYELEM] Ez nem jelenti az összes lehetséges jelszó "
        "kipróbálását."
    )

    return {
        "found": False,
        "skipped": False,
        "attempts": attempts,
        "password": None,
        "wordlist_attempts": wordlist_attempts,
        "extra_attempts": extra_attempts,
        "seconds": elapsed,
    }
# ---------------------------------------------------------------------
# Külön, feltölthető szólista-audit
# ---------------------------------------------------------------------

def run_password_audit(
    wordlist: bytes,
    alphabet: str,
    max_length: int,
    dictionary_limit: int,
    brute_force_limit: int,
    log: Callable[[str], None],
    show_guess: Callable[..., None] | None = None,
) -> dict[str, Any]:
    """
    Először a feltöltött UTF-8 szólista jelöltjeit próbálja,
    majd találat hiányában korlátozott kombinációpróbát futtat.
    Kizárólag a helyi keys/private.json fájlt vizsgálja.
    """

    private_path = KEYS / "private.json"

    if not private_path.is_file():
        raise ValueError(
            "Nem található helyi kulcs. Előbb indítsd el a bemutatót."
        )

    if len(wordlist) > MAX_WORDLIST_BYTES:
        raise ValueError(
            f"A szólista legfeljebb {MAX_WORDLIST_BYTES // (1024 * 1024)} MB lehet."
        )

    if not 1 <= dictionary_limit <= MAX_WORDLIST_GUESSES:
        raise ValueError(
            f"A szólista korlátja 1 és {MAX_WORDLIST_GUESSES} közé essen."
        )

    if not 1 <= max_length <= MAX_BRUTE_FORCE_LENGTH:
        raise ValueError(
            f"A maximális hossz 1 és {MAX_BRUTE_FORCE_LENGTH} közé essen."
        )

    if not 1 <= brute_force_limit <= MAX_BRUTE_FORCE_ATTEMPTS:
        raise ValueError(
            f"A kombinációpróba legfeljebb "
            f"{MAX_BRUTE_FORCE_ATTEMPTS} jelöltet vizsgálhat."
        )

    alphabet = "".join(dict.fromkeys(alphabet))
    if not alphabet:
        raise ValueError("A karakterkészlet nem lehet üres.")

    if len(alphabet) > MAX_ALPHABET_SIZE:
        raise ValueError(
            f"A karakterkészlet legfeljebb "
            f"{MAX_ALPHABET_SIZE} különböző karaktert tartalmazhat."
        )

    try:
        text = wordlist.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("A szólista legyen UTF-8 kódolású.") from exc

    candidates: list[str] = []
    seen: set[str] = set()
    truncated = False

    for candidate in text.splitlines():
        if not candidate.strip() or candidate in seen:
            continue

        if len(candidates) >= dictionary_limit:
            truncated = True
            break

        seen.add(candidate)
        candidates.append(candidate)

    if not candidates:
        raise ValueError("A szólista nem tartalmaz próbálható jelszót.")

    total_possible = sum(
        len(alphabet) ** length
        for length in range(1, max_length + 1)
    )

    combinations: list[str] = []
    for length in range(1, max_length + 1):
        for chars in product(alphabet, repeat=length):
            if len(combinations) >= brute_force_limit:
                break
            combinations.append("".join(chars))

        if len(combinations) >= brute_force_limit:
            break

    total_guesses = len(candidates) + len(combinations)

    log("[AUDIT] Kizárólag a keys/private.json kulcsot vizsgálom.")
    log(
        f"[AUDIT] Szólista-jelöltek: {len(candidates)}; "
        f"kombinációpróba: legfeljebb {len(combinations)}."
    )

    started = time.perf_counter()

    for index, candidate in enumerate(candidates, start=1):
        if show_guess is not None:
            show_guess(
                candidate,
                index,
                total_guesses,
                "Feltöltött szólista",
            )

        try:
            private_key = load_private_key(
                private_path,
                candidate.encode("utf-8"),
            )
        except ValueError:
            if index == 1 or index % 25 == 0:
                log(
                    f"[AUDIT] Szólista: {index}/{len(candidates)} "
                    f"— {candidate!r}"
                )
            continue

        del private_key
        elapsed = time.perf_counter() - started
        log(f"[TALÁLAT] A jelszó: {candidate!r}")
        log(f"[INFO] Szólista-próbák: {index}; idő: {elapsed:.2f} mp.")

        return {
            "found": True,
            "stage": "szólista",
            "password": candidate,
            "dictionary_attempts": index,
            "brute_force_attempts": 0,
            "seconds": elapsed,
        }

    if truncated:
        log(
            "[FIGYELEM] A feltöltött szólista egy része kimaradt "
            "az 1000 jelöltes korlát miatt."
        )

    log("[INFO] A feltöltött szólista nem találta meg a jelszót.")
    log("[AUDIT] Elindul a korlátozott kombinációpróba.")

    for index, candidate in enumerate(combinations, start=1):
        display_attempt = len(candidates) + index

        if show_guess is not None:
            show_guess(
                candidate,
                display_attempt,
                total_guesses,
                "Korlátozott kombinációpróba",
            )

        try:
            private_key = load_private_key(
                private_path,
                candidate.encode("utf-8"),
            )
        except ValueError:
            if index % 25 == 0:
                log(
                    f"[AUDIT] Kombinációk: {index}/{len(combinations)} "
                    f"— {candidate!r}"
                )
            continue

        del private_key
        elapsed = time.perf_counter() - started
        log(f"[TALÁLAT] A jelszó: {candidate!r}")
        log(f"[INFO] Kombinációpróbák: {index}; idő: {elapsed:.2f} mp.")

        return {
            "found": True,
            "stage": "kombinációpróba",
            "password": candidate,
            "dictionary_attempts": len(candidates),
            "brute_force_attempts": index,
            "seconds": elapsed,
        }

    elapsed = time.perf_counter() - started
    search_complete = total_possible <= len(combinations)

    if search_complete:
        log(
            f"[INFO] A megadott karakterekkel és hosszokkal "
            f"mind a {len(combinations)} kombinációt kipróbálta."
        )
    else:
        log(
            f"[FIGYELEM] A kombinációpróba elérte a "
            f"{brute_force_limit} jelöltes korlátot."
        )
        log("[INFO] Nem történt meg minden lehetséges jelszó kipróbálása.")

    log("[KÉSZ] A vizsgált jelöltek között nem volt találat.")

    return {
        "found": False,
        "stage": None,
        "password": None,
        "dictionary_attempts": len(candidates),
        "brute_force_attempts": len(combinations),
        "seconds": elapsed,
    }


# ---------------------------------------------------------------------
# Frissítési és támadási folyamat
# ---------------------------------------------------------------------

def build_attack_sentence(scenario: dict[str, str]) -> str:
    """Visszaadja a támadási próbához tartozó teljes mondatot."""
    text = scenario.get("text", "").strip()

    if not text:
        raise ValueError(
            "A támadási próbából hiányzik a 'text' mező."
        )

    return ensure_period(text)


def scene(
    *,
    stage: str,
    title: str,
    who: str,
    what: str,
    where: str = "",
    progress: int,
    why: str = "",
    outcome: str = "",
    outcome_ok: bool = True,
) -> dict[str, Any]:
    """Egy bemutató-jelenet adatai; a UI ezt rajzolja ki."""
    return {
        "stage": stage,
        "title": title,
        "who": who,
        "what": what,
        "where": where,
        "why": why,
        "outcome": outcome,
        "outcome_ok": outcome_ok,
        "progress": max(0, min(100, int(progress))),
    }


def run_pipeline(
    firmware: bytes,
    password: str,
    filename: str,
    log: Callable[[str], None],
    show_guess: Callable[..., None],
) -> Generator[dict[str, Any], None, None]:
    """A firmware-frissítés éles folyamatát mutatja be, a helyi végrehajtás állapotától függetlenül."""

    log("[INFO] Elindult a firmware-frissítési folyamat bemutatása.")

    before = read_installed_version(STATE)
    version = before + 1
    today = date.today().isoformat()

    result: dict[str, Any] = {
        "fingerprint": "",
        "created": False,
        "before": before,
        "version": version,
        "firmware_size": len(firmware),
        "expected_hash": "",
        "trace": [],
        "error": None,
        "error_text": "",
        "after": before,
        "attacks": [],
        "password_attack": None,
    }

    # 1. Build és tesztelés.
    yield scene(
        stage="factory",
        title="1. Firmware-build és tesztelés",
        who="Gyártóvállalat",
        what=(
            "A CI/build-rendszer a forráskódból lefordítja a firmware-t, "
            "lefuttatja a teszteket, és reprodukálható bináris fájlt állít elő. "
            f"A kiadási artefaktum most a {filename} fájl ({len(firmware)} bájt)."
        ),
        where=filename,
        why=(
            "Csak a tesztelt, reprodukálható build kerülhet aláírásra és kiadásra, "
            "így a kiadott kód visszavezethető a forráskódra."
        ),
        progress=4,
    )

    # 2. Kiadói aláírókulcs.
    yield scene(
        stage="keys",
        title="2. Kiadói aláírókulcs",
        who="Gyártóvállalat",
        what=(
            "A kiadói privát kulcs HSM-ben vagy kulcskezelő szolgáltatásban van, "
            "és nem hagyja el azt. Aláírást csak a kiadási szerver kérhet, "
            "emberi jóváhagyással vagy több aláírós ellenőrzéssel."
        ),
        where="HSM / kulcskezelő szolgáltatás",
        why=(
            "Ha a privát kulcs kiszivárog, bármely hamis firmware elfogadható lenne "
            "a valódi gyártói aláírással, ezért a kulcsot a legszigorúbban kell védeni."
        ),
        progress=10,
    )

    private_key, fingerprint, created = ensure_keys(password, log)
    result["fingerprint"] = fingerprint
    result["created"] = created

    key_message = (
        "Új, jelszóval védett helyi demókulcs készült."
        if created
        else "A meglévő helyi demókulcs megnyílt."
    )
    log(f"[INFO] Kulcsállapot: {key_message}")

    # 3. Manifest és digitális aláírás.
    yield scene(
        stage="signing",
        title="3. Manifest és digitális aláírás",
        who="Gyártóvállalat",
        what=(
            "A kiadási szerver manifestet állít elő, amely tartalmazza a célmodellt, "
            "a verziót, a kiadás dátumát és a firmware SHA-256 lenyomatát. "
            "A manifestet a privát kulccsal aláírja."
        ),
        where="manifest",
        why=(
            "Az aláírás hitelesíti a manifest tartalmát és a firmware-hez való kötését. "
            "Nem titkosítja a firmware-t."
        ),
        progress=18,
    )

    try:
        bundle = create_bundle(
            firmware,
            private_key,
            DEVICE_MODEL,
            version,
            f"{version}.0",
            today,
        )
    finally:
        del private_key

    result["expected_hash"] = bundle.manifest["firmware_sha256"]

    log("[OK] Elkészült az aláírt firmware-csomag.")
    log(f"[INFO] Csomagverzió: {version}; dátum: {today}.")
    log(f"[INFO] Firmware SHA-256: {result['expected_hash']}.")

    # 4. Publikálás a frissítési szolgáltatásban.
    yield scene(
        stage="delivery",
        title="4. Publikálás a frissítési szolgáltatásban",
        who="Gyártóvállalat",
        what=(
            "A kiadási szolgáltatás a verziózott, aláírt csomagot HTTPS-en "
            "publikálja a frissítési tárhelyre vagy CDN-re. A közzététel "
            "fokozatosan (staged rollout) történik: előbb kis tesztcsoport, "
            "majd szélesebb eszközkör."
        ),
        where="frissítési tárhely / CDN",
        why=(
            "A fokozatos kiadás korlátozza a hibás frissítés hatását, "
            "és lehetővé teszi a leállítást, ha probléma derül ki."
        ),
        progress=27,
    )

    write_bundle(bundle, OUT)
    trusted_public_key = load_public_key(KEYS / "public.hex")
    log("[OK] A csomag elmentve az out/ mappába.")

    # 5. Letöltés az eszközön.
    yield scene(
        stage="uploading",
        title="5. Csomag lekérése az eszközön",
        who="Eszköz",
        what=(
            "Az eszköz frissítési kliense lekéri, hogy van-e elérhető frissítés "
            "a modelljéhez, majd HTTPS-en letölti a csomagot. Részleges letöltést "
            "az eszköz nem telepít."
        ),
        where="frissítési szolgáltatás",
        why=(
            "A TLS védi az átvitelt, de a végső bizalmat a csomag aláírásának "
            "ellenőrzése adja, nem a csatorna."
        ),
        progress=34,
    )
    log("[INFO] A csomag az eszköz oldalán ellenőrzésre kész.")

    # 6. Bootloader-ellenőrzés az eszközön.
    yield scene(
        stage="downloading",
        title="6. Bootloader-ellenőrzés",
        who="Eszköz",
        what=(
            "A bootloader a gyártásban beégetett publikus kulccsal ellenőrzi "
            "a manifest aláírását, majd a modellazonosítót, a verziót, "
            "a firmware méretét és SHA-256 lenyomatát."
        ),
        where="beégetett publikus kulcs",
        why=(
            "A publikus kulcsot gyártáskor kell rögzíteni, nem a letöltött "
            "csomagból elfogadni, különben bármely támadó saját kulcsot adhatna meg."
        ),
        progress=41,
    )

    # 7. Csomagellenőrzés.
    yield scene(
        stage="checking",
        title="7. Csomagellenőrzés",
        who="Eszköz",
        what=(
            "Az eszköz ellenőrzi az aláírást, a csomag felépítését, "
            "a modellazonosítót, a firmware-méretet, a SHA-256 lenyomatot "
            "és a verziót. A verziónak nagyobbnak kell lennie az eddigi legmagasabbnál "
            "(anti-rollback)."
        ),
        where="eszköz oldali ellenőrző",
        why=(
            "Az anti-rollback megakadályozza, hogy egy régi, sebezhető firmware "
            "visszatöltődjön, még akkor is, ha az aláírása érvényes."
        ),
        progress=46,
    )

    try:
        _, trace = verify_with_trace(
            bundle,
            trusted_public_key,
            STATE,
            DEVICE_MODEL,
            _log=[],
        )
        result["trace"] = list(trace or [])
        log("[OK] A helyi csomag átment az ellenőrzésen.")
    except UpdateRejected as exc:
        error_name = type(exc).__name__
        result["trace"] = list(getattr(exc, "trace", []) or [])
        result["error"] = error_name
        result["error_text"] = EXCEPTION_EXPLANATIONS.get(error_name, "")

        log(f"[HIBA] Az ellenőrző elutasította a csomagot: {error_name}.")
        if result["error_text"]:
            log(f"[INFO] {result['error_text']}")

    log_trace(result["trace"], log)

    # Az ellenőrzési lépések részletes megjelenítése.
    for step in result["trace"]:
        index = int(get_field(step, "index", 0))
        passed = bool(get_field(step, "passed", False))

        description = VERIFY_EXPLANATIONS.get(
            index,
            {
                "title": f"{index}/5 — Ellenőrzés",
                "what": "Az eszköz ellenőriz egy csomagadatot.",
                "why": "Az ellenőrzési nyomvonal rögzíti az eredményt.",
            },
        )

        yield scene(
            stage="checking",
            title=description["title"],
            who="Eszköz",
            what=description["what"],
            where="",
            why=description["why"],
            outcome=(
                "✅ Az ellenőrzés sikeres."
                if passed
                else "⛔ Az ellenőrzés sikertelen."
            ),
            outcome_ok=passed,
            progress=min(75, 47 + index * 5),
        )

    result["after"] = read_installed_version(STATE)
    log(f"[INFO] Helyi verzió előtte: {result['before']}.")
    log(f"[INFO] Helyi verzió utána: {result['after']}.")

    # 8. Telepítés A/B partícióra.
    if result["error"] is None:
        yield scene(
            stage="accepted",
            title="8. Telepítés az inaktív partícióra",
            who="Eszköz",
            what=(
                "A sikeresen ellenőrzött image az inaktív partícióra kerül, "
                "majd az eszköz újraindul, és az új firmware-t próbaként indítja."
            ),
            where="inaktív A/B partíció",
            why=(
                "Ha az új firmware nem indul el helyesen, az eszköz automatikusan "
                "visszaáll a korábbi, működő partícióra."
            ),
            outcome="✅ Az ellenőrzés sikeres, a telepítés elindulhat.",
            outcome_ok=True,
            progress=78,
        )
    else:
        yield scene(
            stage="error",
            title="Az ellenőrzés sikertelen, a csomag eldobva",
            who="Eszköz",
            what=result["error_text"] or "Az ellenőrző elutasította a csomagot.",
            where="",
            why="Elutasított csomag után a jelenlegi firmware marad érvényben.",
            outcome="⛔ A telepítés nem indul el.",
            outcome_ok=False,
            progress=78,
        )

    # 9. Módosított csomagok elutasítása.
    yield scene(
        stage="attacker",
        title="9. Módosított csomagok ellenőrzése",
        who="Támadó",
        what=(
            "Módosított firmware, manifest, aláírókulcs és visszalépést célzó "
            "csomagok érkeznek az eszközhöz, a valódi frissítési csatornán keresztül."
        ),
        where="eszköz oldali ellenőrző",
        why=(
            "A cél annak igazolása, hogy az aláírás-, tartalom-, modell- "
            "és verzióellenőrzés mindegyiket elutasítja."
        ),
        progress=80,
    )

    attack_iterator = iter(
        run_attacks(
            bundle,
            trusted_public_key,
            DEVICE_MODEL,
            STATE,
        )
    )

    attack_passes: list[bool] = []

    for index, scenario in enumerate(ATTACK_SCENARIOS, start=1):
        attack = next(attack_iterator, None)

        if attack is not None:
            result["attacks"].append(attack)

        passed = bool(get_field(attack, "passed", False))
        actual = str(get_field(attack, "actual", "") or "").casefold()
        attack_passes.append(passed)

        scenario_title = scenario["title"]

        if passed:
            outcome = "✅ Az ellenőrző elutasította a módosított csomagot."
            log(f"[OK] {index}/5 — {scenario_title}: elutasítva.")
        elif actual == "accepted":
            outcome = "❌ A módosított csomag átment az ellenőrzésen."
            log(f"[HIBA] {index}/5 — {scenario_title}: elfogadva.")
        else:
            outcome = "⚠️ A kapott eredmény eltér a várt eredménytől."
            log(f"[FIGYELEM] {index}/5 — {scenario_title}: ellenőrizendő.")

        yield scene(
            stage="attacker",
            title=f"Teszt {index}/5 — {scenario_title}",
            who="Támadó",
            what=build_attack_sentence(scenario),
            where="",
            why="",
            outcome=outcome,
            outcome_ok=passed,
            progress=min(91, 80 + index * 2),
        )

    # 10. Kulcsjelszó-ellenőrzés (csak a helyi kulcsra).
    yield scene(
        stage="bruteforce",
        title="10. Kulcsjelszó-ellenőrzés",
        who="Támadó",
        what=(
            "Gyenge vagy újrahasznált jelszavakkal szemben próbálkozik a "
            "helyi kulcs megnyitásával. Éles környezetben a kulcs HSM-ben van, "
            "így ilyen támadás nem férhet hozzá."
        ),
        where="helyi kulcsfájl",
        why=(
            "A kulcs védelme csak a jelszó erősségétől és a hozzáférés-korlátozástól "
            "függ, ezért HSM-et vagy kulcskezelőt használunk éles rendszerben."
        ),
        progress=92,
    )

    password_attack = run_automatic_password_attack(
        log,
        show_guess,
    )
    result["password_attack"] = password_attack

    if password_attack["found"]:
        found_password = password_attack["password"]

        yield scene(
            stage="bruteforce-success",
            title="A helyi kulcs jelszava megtalálható volt",
            who="Támadó",
            what="Az egyik kipróbált jelölt megnyitotta a helyi kulcsot.",
            where="helyi kulcsfájl",
            why="A gyakori vagy újrahasznált jelszó gyengíti a kulcs védelmét.",
            outcome=f"Találat: {found_password}",
            outcome_ok=False,
            progress=98,
        )
    else:
        yield scene(
            stage="bruteforce-failed",
            title="A kulcsjelszó-próba befejeződött",
            who="Támadó",
            what=(
                f"A folyamat {password_attack['attempts']} jelöltet próbált "
                "a helyi kulcsfájlon."
            ),
            where="helyi kulcsfájl",
            why=(
                "Az eredmény csak a kipróbált jelöltekre vonatkozik; "
                "nem igazolja, hogy minden lehetséges jelszó sikertelen lenne."
            ),
            outcome="A kipróbált jelöltek között nem volt találat.",
            outcome_ok=True,
            progress=98,
        )

    firmware_test_count = 1 + len(ATTACK_SCENARIOS)
    firmware_pass_count = int(result["error"] is None) + sum(attack_passes)

    attack_tests_ok = (
        len(attack_passes) == len(ATTACK_SCENARIOS)
        and all(attack_passes)
    )
    firmware_tests_ok = result["error"] is None and attack_tests_ok
    overall_ok = firmware_tests_ok and not password_attack["found"]

    if password_attack["found"]:
        password_summary = "A helyi kulcs jelszavára talált egyező jelöltet."
    else:
        password_summary = (
            f"{password_attack['attempts']} helyi jelölt között "
            "nem volt találat."
        )

    log(
        f"[KÉSZ] Csomagellenőrzés és módosítási tesztek: "
        f"{firmware_pass_count}/{firmware_test_count}."
    )
    log(f"[KÉSZ] Jelszópróba: {password_summary}")

    yield scene(
        stage="done",
        title="A folyamat összesítése",
        who="Összesítés",
        what=(
            f"{firmware_pass_count}/{firmware_test_count} csomagellenőrzési "
            f"teszt sikeres. {password_summary}"
        ),
        where="",
        why=(
            "Az aláírás, a manifest, a lenyomat, a verzióellenőrzés és a "
            "kulcsvédelem együtt alkotja a védelmi láncot."
        ),
        outcome_ok=overall_ok,
        progress=100,
    )

# ---------------------------------------------------------------------
# Képernyőfrissítések
# ---------------------------------------------------------------------

def present(
    *,
    stage: str,
    title: str,
    who: str,
    what: str,
    where: str,
    progress: int,
    why: str = "",
    outcome: str = "",
    outcome_ok: bool = True,
    hold_seconds: float | None = None,
) -> None:
    """Frissíti a jelenetet, majd olvasási időt hagy a képernyőn."""

    story = {
        "stage": stage,
        "title": title,
        "who": who,
        "what": what,
        "where": where,
        "why": why,
        "outcome": outcome,
        "outcome_ok": outcome_ok,
    }

    st.session_state["story_state"] = story
    safe_progress = max(0, min(100, int(progress)))

    st.session_state["story_progress"] = safe_progress
    draw_story(story_placeholder, story)
    progress_bar.progress(safe_progress, text=title)

    if hold_seconds is None:
        hold_seconds = 0 if stage == "idle" else STEP_SECONDS

    if hold_seconds > 0:
        time.sleep(hold_seconds)


def show_guess(
    candidate: str,
    attempt: int,
    total: int,
    phase: str = "Jelszópróba",
) -> None:
    """Megjeleníti a támadó éppen próbált jelszójelöltjét."""

    percentage = min(100, max(0, 100 * attempt / max(total, 1)))

    markup = (
        '<div class="live-guess">'
        f'<div class="live-guess-label">{html.escape(phase.upper())} '
        "— ÉPPEN PRÓBÁLT JELSZÓ</div>"
        '<div class="live-guess-row">'
        f'<div class="live-guess-value">{safe_text(candidate)}</div>'
        f'<div class="live-guess-count">{attempt} / {total}</div>'
        "</div>"
        '<div class="guess-progress">'
        f'<span style="width:{percentage:.1f}%"></span>'
        "</div>"
        "</div>"
    )

    brute_guess_placeholder.markdown(markup, unsafe_allow_html=True)

    if phase.startswith("Szólista") or phase.startswith("Kiegészítő"):
        progress = min(97, 92 + int(5 * attempt / max(total, 1)))
        progress_text = f"{phase}: {attempt}/{total}"
    else:
        progress = int(100 * attempt / max(total, 1))
        progress_text = f"{phase}: {attempt}/{total}"

    progress_bar.progress(progress, text=progress_text)
    time.sleep(AUTO_ATTACK_DELAY_SECONDS)


# ---------------------------------------------------------------------
# Felület
# ---------------------------------------------------------------------

inject_css()

st.markdown(
    """
    <div class="hero">
      <div class="hero-copy">
        <div class="hero-kicker">ALÁÍRÁS · ELLENŐRZÉS · TÁMADÁSI PRÓBÁK</div>
        <h1>Biztonságos firmware-frissítés</h1>
        <p>
          Kövesd a csomag útját a gyártótól az eszközig,
          nézd meg az ellenőrzéseket és az öt támadási próbát.
        </p>
      </div>
      <div class="hero-side">
        <div class="hero-chip"><span class="hero-chip-dot"></span>HELYI TESZTKÖRNYEZET</div>
        <div class="hero-chip">📟 ESZKÖZMODELL · demo-device</div>
        <div class="hero-chip">⏱️ LÉPÉSEK · {STEP_SECONDS} MÁSODPERC</div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="section-heading">'
    "<h2>Frissítés indítása</h2>"
    '<span class="section-hint">Firmware-fájl + aláírókulcs-jelszó</span>'
    "</div>",
    unsafe_allow_html=True,
)

with st.form("update_form", clear_on_submit=False):
    input_file_col, password_col, action_col = st.columns(
        [1.25, 1, 0.8],
        gap="large",
    )

    firmware_file = input_file_col.file_uploader(
        "Firmware-fájl",
        help="A kiválasztott fájlt a program bájtokként olvassa be.",
        key="firmware_upload",
    )

    signing_password = password_col.text_input(
        "Aláírókulcs jelszava",
        type="password",
        help=(
            "Használj külön bemutató jelszót. "
            "A jelszópróba a helyi kulcsot vizsgálja."
        ),
        key="signing_password",
    )

    action_col.markdown(
        '<div class="section-kicker">INDÍTÁS</div>',
        unsafe_allow_html=True,
    )
    run_demo = action_col.form_submit_button(
        "Frissítés és támadási próbák",
        type="primary",
        use_container_width=True,
    )

    st.caption(
        f"Modell: {DEVICE_MODEL} · "
        f"A csomag az out/ mappába kerül · "
        f"A helyi verzió a device/device_state.json fájlban tárolódik."
    )


# Az animáció és a terminál ugyanabban a desktop nézetben marad.
story_col, terminal_col = st.columns([1.65, 1], gap="large")

with story_col:
    st.markdown(
        '<div class="section-heading">'
        "<h2>Élő folyamat</h2>"
        '<span class="section-hint">Gyártó → internet → eszköz</span>'
        "</div>",
        unsafe_allow_html=True,
    )

    progress_bar = st.progress(
        int(st.session_state.get("story_progress", 0)),
        text="Várakozás a bemenetekre",
    )

    story_placeholder = st.empty()
    brute_guess_placeholder = st.empty()

    default_story = {
        "stage": "idle",
        "title": "Készen állunk",
        "who": "",
        "what": "Válassz firmware-fájlt és add meg a kulcs jelszavát.",
        "where": "",
        "why": "A program megmutatja az aláírást, az ellenőrzést és a támadási próbákat.",
        "outcome": "",
        "outcome_ok": True,
    }

    current_story = st.session_state.get("story_state", default_story)
    draw_story(story_placeholder, current_story)

with terminal_col:
    st.markdown(
        '<div class="panel-heading">'
        "<strong>Technikai események</strong>"
        '<span class="panel-live">ÉLŐ NAPLÓ</span>'
        "</div>",
        unsafe_allow_html=True,
    )

    terminal_placeholder = st.empty()
    terminal = Terminal(terminal_placeholder)


# ---------------------------------------------------------------------
# Kulcsok és helyi verzió nullázása
# ---------------------------------------------------------------------

with st.expander("Haladó: kulcsok és helyi verzió nullázása", expanded=False):
    st.warning(
        "Törli a teljes keys/ mappát, és 0-ra állítja a helyi eszközverziót."
    )

    confirm_reset = st.checkbox(
        "Megerősítem a kulcsok törlését",
        key="confirm_reset",
    )

    reset_button = st.button(
        "Demóállapot nullázása",
        disabled=not confirm_reset,
        key="reset_demo",
    )

    reset_feedback = st.empty()


# ---------------------------------------------------------------------
# Gombműveletek
# ---------------------------------------------------------------------

if run_demo:
    terminal.clear()
    brute_guess_placeholder.empty()
    progress_bar.progress(0, text="A frissítés indul")
    terminal.write("[INFO] Új firmware-frissítés indul.")

    if firmware_file is None or not signing_password:
        message = "Válassz firmware-fájlt, és add meg a kulcs jelszavát."
        terminal.write(f"[HIBA] {message}")

        present(
            stage="error",
            title="Hiányzik egy bemenet",
            who="",
            what=message,
            where="",
            why="A csomag elkészítéséhez fájlra és jelszóra van szükség.",
            outcome="Javítsd a bemeneteket, majd próbáld újra.",
            outcome_ok=False,
            progress=0,
        )
    else:
        try:
            firmware_bytes = firmware_file.getvalue()

            if len(firmware_bytes) > MAX_FIRMWARE_BYTES:
                raise ValueError("A firmware-fájl legfeljebb 64 MB lehet.")

            if not firmware_bytes:
                raise ValueError("A kiválasztott firmware-fájl üres.")

            scenes: list[dict[str, Any]] = []
            pipeline = run_pipeline(
                firmware_bytes,
                signing_password,
                firmware_file.name,
                terminal.write,
                show_guess,
            )

            for current_scene in pipeline:
                scenes.append(current_scene)

                st.session_state["story_state"] = current_scene
                st.session_state["story_progress"] = current_scene["progress"]

                draw_story(story_placeholder, current_scene)
                progress_bar.progress(
                    current_scene["progress"],
                    text=current_scene["title"],
                )

                time.sleep(STEP_SECONDS)

            st.session_state["scenes"] = scenes
            st.session_state["scene_index"] = max(0, len(scenes) - 1)

        except (OSError, ValueError) as exc:
            message = str(exc)
            terminal.write(f"[HIBA] {type(exc).__name__}: {message}")

            present(
                stage="error",
                title="A folyamat leállt",
                who="Helyi program",
                what=message,
                where="frissítési folyamat",
                why="A program nem tudta folytatni a műveletet.",
                outcome=(
                    "Ellenőrizd a fájlt, a jelszót "
                    "és a mappajogosultságokat."
                ),
                outcome_ok=False,
                progress=0,
            )

        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            terminal.write(f"[HIBA] Váratlan hiba: {message}")

            present(
                stage="error",
                title="Váratlan hiba történt",
                who="Helyi program",
                what=message,
                where="frissítési folyamat",
                why="A folyamat nem tudott rendben befejeződni.",
                outcome="A részleteket a technikai napló tartalmazza.",
                outcome_ok=False,
                progress=0,
            )


if reset_button:
    terminal.write("[INFO] Kulcsok és helyi verzió nullázása.")

    try:
        if KEYS.exists():
            shutil.rmtree(KEYS)
            terminal.write("[OK] A teljes keys/ mappa törölve.")
        else:
            terminal.write("[INFO] Nem volt keys/ mappa.")

        STATE.parent.mkdir(parents=True, exist_ok=True)
        write_installed_version(STATE, 0)

        reset_feedback.success(
            "A keys/ mappa törölve, a helyi verzió 0-ra állítva."
        )

        brute_guess_placeholder.empty()
        present(
            stage="idle",
            title="A bemutató újrakezdésre kész",
            who="",
            what="A kulcsok törlődtek, a helyi verzió 0.",
            where="",
            why="A következő indítás új aláírókulcsot készít.",
            outcome="Újraindíthatod a frissítési folyamatot.",
            outcome_ok=True,
            progress=0,
        )

    except OSError as exc:
        message = f"{type(exc).__name__}: {exc}"
        terminal.write(f"[HIBA] Nullázás: {message}")
        reset_feedback.error(
            f"Nem sikerült a nullázás: {type(exc).__name__}."
        )

if "scenes" in st.session_state and st.session_state["scenes"]:
    scenes = st.session_state["scenes"]
    idx = st.session_state.get("scene_index", 0)
    idx = max(0, min(idx, len(scenes) - 1))
    st.session_state["scene_index"] = idx
    current = scenes[idx]

    progress_bar.progress(current["progress"], text=current["title"])
    draw_story(story_placeholder, current)

    prev_col, counter_col, next_col = st.columns([1, 2, 1])
    if prev_col.button("← Előző", disabled=idx == 0, key="scene_prev"):
        st.session_state["scene_index"] = idx - 1
        st.rerun()
    counter_col.markdown(
        f"<div style='text-align:center'>{idx + 1} / {len(scenes)}</div>",
        unsafe_allow_html=True,
    )
    if next_col.button("Következő →", disabled=idx == len(scenes) - 1, key="scene_next"):
        st.session_state["scene_index"] = idx + 1
        st.rerun()
        
        
        
st.markdown(
    '<div class="footer-note">'
    "GYÁRTÓ → INTERNET → ESZKÖZ · ALÁÍRÁS · ELLENŐRZÉS · TÁMADÁSI PRÓBÁK"
    "</div>",
    unsafe_allow_html=True,
)