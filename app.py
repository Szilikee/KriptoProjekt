from __future__ import annotations

import hashlib
import html
import re
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

# Az automatikus próba összesen legfeljebb ennyi jelöltet vizsgál:
# előbb a jelszavak.txt első sorait, a maradék helyet kiegészítő jelöltek töltik ki.
AUTO_ATTACK_MAX_GUESSES = 200
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
            "A tesztelő módosít egy bájtot a firmware-ben. Az újraszámított "
            "SHA-256-lenyomat eltér a manifestben rögzítettől, ezért az eszköz "
            "elutasítja a csomagot."
        ),
    },
    {
        "title": "Verzióadat módosítása",
        "text": (
            "A tesztelő átírja a manifest verzióadatát. Az aláírás ellenőrzése "
            "így sikertelen, ezért az eszköz elutasítja a csomagot."
        ),
    },
    {
        "title": "Aláírás idegen kulccsal",
        "text": (
            "A tesztelő idegen privát kulccsal írja alá a csomagot. Az eszköz "
            "megbízható gyártói publikus kulcsa nem igazolja az aláírást, "
            "ezért az eszköz elutasítja a csomagot."
        ),
    },
    {
        "title": "Régebbi kiadás visszatelepítése",
        "text": (
            "A tesztelő egy korábban érvényesen aláírt, de a telepítettnél "
            "régebbi firmware-t próbál telepíteni. A visszalépés elleni "
            "védelem elutasítja a csomagot."
        ),
    },
    {
        "title": "Aláírás eltávolítása",
        "text": (
            "A tesztelő eltávolítja a digitális aláírást a csomagból. "
            "Aláírás nélkül az eszköz nem tudja hitelesíteni a kiadást, "
            "ezért elutasítja."
        ),
    },
]


# A "what" mondatrészek állítmánnyal kezdődnek; a szereplő ("Az eszköz")
# automatikusan előkerül a mondat elejére.
VERIFY_EXPLANATIONS = {
    1: {
        "title": "1/5 — Gyártói aláírás",
        "what": (
            "a megbízható gyártói kulccsal ellenőrzi, hogy a csomagot a gyártó "
            "írta-e alá, és az aláírt adatok azóta nem változtak-e meg."
        ),
        "why": "Így felismeri az ismeretlen eredetű vagy utólag módosított csomagot.",
    },
    2: {
        "title": "2/5 — A csomag felépítése",
        "what": (
            "ellenőrzi, hogy a csomag felépítése megfelelő-e, és tartalmazza-e "
            "az összes kötelező adatot."
        ),
        "why": "Hibás vagy hiányos csomagot nem biztonságos telepíteni.",
    },
    3: {
        "title": "3/5 — A megfelelő eszközmodell",
        "what": "ellenőrzi, hogy a firmware pontosan az ő modelljéhez készült-e.",
        "why": "Másik modellhez készült firmware-t nem telepít.",
    },
    4: {
        "title": "4/5 — A firmware-fájl épsége",
        "what": (
            "összeveti a firmware méretét és SHA-256-lenyomatát a csomagban "
            "megadott értékekkel."
        ),
        "why": (
            "Ha a fájl megsérült vagy módosították, az értékek nem egyeznek, "
            "ezért a csomagot elutasítja."
        ),
    },
    5: {
        "title": "5/5 — A firmware verziója",
        "what": "összeveti a csomag verzióját a jelenleg telepített verzióval.",
        "why": "Csak újabb verziót telepít, így régebbi firmware-re nem lehet visszalépni.",
    },
}


# ---------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------

ICONS = {
    "factory": '<path d="M2 20a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V8l-7 5V8l-7 5V4a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2Z"/><path d="M17 18h1"/><path d="M12 18h1"/><path d="M7 18h1"/>',
    "cloud": '<path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/>',
    "chip": '<rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/>',
    "key": '<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/>',
    "box": '<path d="M11 21.73a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73z"/><path d="M12 22V12"/><path d="m3.3 7 8.7 5 8.7-5"/>',
    "shield": '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
    "check": '<path d="M20 6 9 17l-5-5"/>',
    "check-circle": '<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>',
    "x-circle": '<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>',
    "bug": '<path d="m8 2 1.88 1.88"/><path d="M14.12 3.88 16 2"/><path d="M9 7.13v-1a3.003 3.003 0 1 1 6 0v1"/><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6"/><path d="M12 20v-9"/><path d="M6.53 9C4.6 8.8 3 7.1 3 5"/><path d="M6 13H2"/><path d="M3 21c0-2.1 1.7-3.9 3.8-4"/><path d="M20.97 5c0 2.1-1.6 3.8-3.5 4"/><path d="M22 13h-4"/><path d="M17.2 17c2.1.1 3.8 1.9 3.8 4"/>',
}


def icon(name: str, size: int = 18) -> str:
    return (
        f'<svg class="ic" width="{size}" height="{size}" viewBox="0 0 24 24" '
        'fill="none" stroke="currentColor" stroke-width="1.8" '
        'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        f"{ICONS[name]}</svg>"
    )


STEP_GROUPS = [
    (
        "Gyártó",
        [
            (1, "Build és tesztelés"),
            (2, "Aláírókulcs"),
            (3, "Manifest és aláírás"),
            (4, "Közzététel"),
        ],
    ),
    (
        "Eszköz",
        [
            (5, "Letöltés"),
            (6, "Bootloader"),
            (7, "Csomagellenőrzés"),
            (8, "Telepítés"),
        ],
    ),
    (
        "Támadási próbák",
        [
            (9, "Módosított csomagok"),
            (10, "Kulcsjelszó-próba"),
        ],
    ),
    ("Eredmény", [(11, "Összesítés")]),
]

STEP_GROUP_OF = {
    number: group for group, items in STEP_GROUPS for number, _ in items
}


APP_CSS = """
:root {
    color-scheme: dark;
    --bg: #070c12;
    --panel: #0b121a;
    --panel-2: #0f1822;
    --line: #1b2733;
    --line-2: #263445;
    --text: #e8eff7;
    --muted: #8a9bad;
    --dim: #5d6e80;
    --cyan: #5dd6e8;
    --cyan-soft: rgba(93, 214, 232, .12);
    --green: #4ade9b;
    --red: #fb7185;
    --amber: #fbbf24;
    --mono: ui-monospace, "JetBrains Mono", Consolas, monospace;
}

html, body, [class*="css"] {
    font-family: Inter, "Segoe UI", system-ui, sans-serif;
}

.stApp {
    background: var(--bg);
    color: var(--text);
}

header[data-testid="stHeader"],
[data-testid="stToolbar"],
[data-testid="stDecoration"],
#MainMenu,
footer {
    display: none !important;
}

main .block-container {
    width: 100%;
    max-width: none !important;
    padding: 1rem clamp(1rem, 2vw, 2.4rem) 1.6rem;
}

.ic {
    flex: 0 0 auto;
    vertical-align: middle;
}

/* Widgetek */

[data-testid="stWidgetLabel"] p {
    color: var(--muted) !important;
    font-size: 12px;
    font-weight: 500;
}

[data-testid="stForm"] {
    padding: .9rem 1rem .7rem;
    border: 1px solid var(--line);
    border-radius: 14px;
    background: var(--panel);
}

[data-testid="stFileUploaderDropzone"] {
    padding: .5rem .8rem;
    border: 1px dashed var(--line-2);
    border-radius: 10px;
    background: transparent;
}

.stTextInput [data-baseweb="input"] {
    border: 1px solid var(--line-2);
    border-radius: 10px;
    background: var(--panel-2);
}

.stButton > button,
[data-testid="stFormSubmitButton"] button,
[data-testid="stPopover"] button {
    min-height: 2.7rem;
    border: 1px solid var(--line-2);
    border-radius: 10px;
    background: transparent;
    color: var(--text);
    font-weight: 600;
    transition: border-color .15s ease, color .15s ease;
}

.stButton > button:hover,
[data-testid="stFormSubmitButton"] button:hover,
[data-testid="stPopover"] button:hover {
    border-color: var(--cyan);
    color: var(--cyan);
}

.stButton > button[kind="primary"],
.stButton > button[data-testid="stBaseButton-primary"],
[data-testid="stFormSubmitButton"] button[kind="primary"],
[data-testid="stFormSubmitButton"] button[kind="primaryFormSubmit"],
[data-testid="stFormSubmitButton"] button[data-testid="stBaseButton-primaryFormSubmit"] {
    border: 0;
    background: var(--cyan);
    color: #06121a;
}

.stButton > button[kind="primary"]:hover,
[data-testid="stFormSubmitButton"] button[kind="primary"]:hover,
[data-testid="stFormSubmitButton"] button[kind="primaryFormSubmit"]:hover {
    background: #7be3f1;
    color: #06121a;
}

.stButton > button:disabled {
    opacity: .35;
}

.btn-spacer {
    height: 1.55rem;
}

/* Fejléc */

.brand {
    display: flex;
    align-items: center;
    gap: 14px;
}

.brand-icon {
    display: grid;
    width: 44px;
    height: 44px;
    place-items: center;
    border: 1px solid #1b4452;
    border-radius: 12px;
    background: #0e2830;
    color: var(--cyan);
}

.brand h1 {
    margin: 0;
    padding: 0;
    color: var(--text);
    font-size: 19px;
    font-weight: 700;
    letter-spacing: -.01em;
    line-height: 1.25;
}

.brand-sub {
    margin-top: 2px;
    color: var(--muted);
    font-size: 13px;
}

.meta {
    display: flex;
    justify-content: flex-end;
    gap: 22px;
    padding-top: 14px;
    color: var(--dim);
    font: 12px var(--mono);
}

.meta b {
    margin-left: 6px;
    color: var(--text);
    font-weight: 600;
}

/* Bal oldali lépéslista */

.stepper {
    padding: .2rem 0;
}

.step-group {
    margin: 1rem 0 .35rem;
    color: var(--muted);
    font-size: 12px;
    font-weight: 600;
}

.step-group:first-child {
    margin-top: 0;
}

.step {
    position: relative;
    padding: 3px 0 9px;
}

.step:not(.last)::before {
    position: absolute;
    top: 28px;
    bottom: -1px;
    left: 11px;
    width: 1px;
    background: var(--line-2);
    content: "";
}

.step.done:not(.last)::before {
    background: rgba(74, 222, 155, .35);
}

.step-row {
    display: flex;
    align-items: center;
    gap: 12px;
}

.step-dot {
    display: grid;
    width: 24px;
    height: 24px;
    flex: 0 0 auto;
    place-items: center;
    border: 1px solid var(--line-2);
    border-radius: 50%;
    background: var(--bg);
    color: var(--dim);
    font-size: 11px;
    font-weight: 600;
}

.step-label {
    color: var(--dim);
    font-size: 14px;
}

.step.done .step-dot {
    border-color: rgba(74, 222, 155, .55);
    background: rgba(74, 222, 155, .08);
    color: var(--green);
}

.step.done .step-label {
    color: var(--text);
}

.step.active .step-dot {
    border-color: var(--cyan);
    background: var(--cyan);
    color: #06121a;
}

.step.active .step-label {
    color: #fff;
    font-weight: 700;
}

.step-segs {
    display: flex;
    gap: 4px;
    margin: 8px 0 0 36px;
}

.step-segs span {
    height: 3px;
    flex: 1;
    border-radius: 3px;
    background: var(--line-2);
}

.step-segs span.on {
    background: var(--cyan);
}

/* Jelenet */

.network-card {
    padding: 12px 14px 14px;
    border: 1px solid var(--line);
    border-radius: 14px;
    background: var(--panel);
}

.network-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 10px;
    color: var(--muted);
    font-size: 12px;
}

.status-pill {
    padding: 4px 13px;
    border: 1px solid rgba(93, 214, 232, .28);
    border-radius: 999px;
    background: var(--cyan-soft);
    color: var(--cyan);
    font-size: 12px;
    font-weight: 600;
}

.status-pill.bad {
    border-color: rgba(251, 113, 133, .35);
    background: rgba(251, 113, 133, .1);
    color: var(--red);
}

.network-scene {
    position: relative;
    height: 190px;
    overflow: hidden;
}

.storyboard.stage-attacker .network-scene,
.storyboard.stage-bruteforce .network-scene,
.storyboard.stage-bruteforce-success .network-scene,
.storyboard.stage-bruteforce-failed .network-scene {
    height: 232px;
}

.pkg-chip {
    position: absolute;
    z-index: 6;
    top: 0;
    right: 0;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 5px 11px;
    border: 1px solid var(--line-2);
    border-radius: 9px;
    background: var(--panel-2);
    color: var(--muted);
    font-size: 12px;
}

.pkg-chip b {
    color: var(--text);
    font-weight: 600;
}

.pkg-state {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    color: var(--cyan);
    font-weight: 600;
}

.pkg-state.bad {
    color: var(--red);
}

.network-route {
    position: absolute;
    z-index: 1;
    top: 114px;
    right: 18%;
    left: 18%;
    height: 1px;
    background: var(--line-2);
}

.scene-node {
    position: absolute;
    z-index: 2;
    top: 48px;
    display: flex;
    width: 30%;
    height: 132px;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 3px;
    border: 1px solid var(--line);
    border-radius: 14px;
    background: var(--panel-2);
    color: var(--dim);
    text-align: center;
    transition: border-color .25s ease, color .25s ease;
}

.scene-node.factory { left: 3%; }
.scene-node.cloud { left: 35%; }
.scene-node.device { right: 3%; }

.scene-ic {
    display: grid;
    width: 44px;
    height: 44px;
    margin-bottom: 5px;
    place-items: center;
    border-radius: 12px;
    background: #111c27;
}

.scene-node strong {
    font-size: 15px;
    font-weight: 700;
}

.scene-node small {
    font-size: 12px;
}

.scene-node.active {
    color: var(--text);
}

.scene-node.active small {
    color: var(--muted);
}

.scene-node.factory.active {
    border-color: rgba(93, 214, 232, .6);
}

.scene-node.factory.active .scene-ic {
    background: rgba(93, 214, 232, .12);
    color: var(--cyan);
}

.scene-node.cloud.active {
    border-color: rgba(167, 139, 250, .6);
}

.scene-node.cloud.active .scene-ic {
    background: rgba(167, 139, 250, .12);
    color: #a78bfa;
}

.scene-node.device.active {
    border-color: rgba(74, 222, 155, .6);
}

.scene-node.device.active .scene-ic {
    background: rgba(74, 222, 155, .12);
    color: var(--green);
}

.stage-bruteforce .scene-node.device.active,
.stage-bruteforce-success .scene-node.device.active,
.stage-bruteforce-failed .scene-node.device.active {
    border-color: rgba(251, 113, 133, .6);
}

.stage-bruteforce .scene-node.device.active .scene-ic,
.stage-bruteforce-success .scene-node.device.active .scene-ic,
.stage-bruteforce-failed .scene-node.device.active .scene-ic {
    background: rgba(251, 113, 133, .12);
    color: var(--red);
}

.moving-package,
.attack-packet {
    position: absolute;
    z-index: 5;
    top: 95px;
    left: 18%;
    display: none;
    width: 38px;
    height: 38px;
    margin-left: -19px;
    place-items: center;
    border: 1px solid rgba(93, 214, 232, .6);
    border-radius: 10px;
    background: #0e2430;
    color: var(--cyan);
}

.attack-packet {
    border-color: rgba(251, 113, 133, .7);
    background: #2a1620;
    color: var(--red);
}

.stage-delivery .moving-package {
    display: grid;
    animation: package-ready .8s ease-in-out infinite alternate;
}

.stage-uploading .moving-package {
    display: grid;
    animation: send-to-cloud 2.4s ease-in-out infinite;
}

.stage-downloading .moving-package {
    display: grid;
    animation: send-to-device 2.4s ease-in-out infinite;
}

.stage-checking .moving-package,
.stage-accepted .moving-package {
    left: 82%;
    display: grid;
}

.stage-attacker .attack-packet {
    display: grid;
    animation: attack-flight 1.8s ease-in-out infinite;
}

.stage-bruteforce .attack-packet {
    display: grid;
    animation: key-flight 1.4s ease-in-out infinite;
}

.stage-checking .scene-node.device::after {
    position: absolute;
    top: 0;
    bottom: 0;
    left: 0;
    width: 2px;
    border-radius: 2px;
    background: var(--cyan);
    box-shadow: 0 0 14px var(--cyan);
    content: "";
    animation: scan-device 1.6s linear infinite;
}

.attacker-figure {
    position: absolute;
    z-index: 4;
    top: 196px;
    left: 50%;
    display: none;
    align-items: center;
    gap: 7px;
    padding: 5px 11px;
    transform: translateX(-50%);
    border: 1px solid rgba(251, 113, 133, .4);
    border-radius: 9px;
    background: #22131b;
    color: var(--red);
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .06em;
}

.stage-attacker .attacker-figure,
.stage-bruteforce .attacker-figure,
.stage-bruteforce-success .attacker-figure,
.stage-bruteforce-failed .attacker-figure {
    display: flex;
}

/* Jelenet alatti szöveg */

.scene-copy {
    padding: 18px 2px 4px;
}

.scene-kicker {
    color: var(--muted);
    font: 12px var(--mono);
    letter-spacing: .02em;
}

.scene-title {
    margin: 6px 0 14px;
    color: #fff;
    font-size: 27px;
    font-weight: 700;
    letter-spacing: -.02em;
    line-height: 1.2;
}

.scene-action {
    color: #d3deea;
    font-size: 16px;
    line-height: 1.6;
}

.scene-why {
    margin-top: 16px;
    padding: 2px 0 2px 16px;
    border-left: 2px solid var(--line-2);
}

.scene-why-label {
    color: var(--muted);
    font-size: 13px;
}

.scene-why-text {
    margin-top: 3px;
    color: #d3deea;
    font-size: 15px;
    line-height: 1.55;
}

.scene-outcome {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    margin-top: 18px;
    padding: 10px 16px;
    border: 1px solid;
    border-radius: 10px;
    font-size: 14px;
    font-weight: 600;
}

.scene-outcome.good {
    border-color: rgba(74, 222, 155, .4);
    background: rgba(74, 222, 155, .07);
    color: var(--green);
}

.scene-outcome.bad {
    border-color: rgba(251, 113, 133, .4);
    background: rgba(251, 113, 133, .07);
    color: var(--red);
}

/* Jelszópróba */

.live-guess {
    margin: 4px 0 6px;
    padding: 11px 14px;
    border: 1px solid rgba(251, 113, 133, .35);
    border-radius: 12px;
    background: rgba(48, 19, 29, .6);
}

.live-guess-label {
    color: var(--red);
    font-size: 10px;
    font-weight: 700;
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
    font: 700 20px var(--mono);
    overflow-wrap: anywhere;
}

.live-guess-count {
    color: #cbd5e1;
    font: 11px var(--mono);
}

.guess-progress {
    height: 4px;
    margin-top: 8px;
    overflow: hidden;
    border-radius: 4px;
    background: rgba(255, 255, 255, .1);
}

.guess-progress span {
    display: block;
    height: 100%;
    border-radius: inherit;
    background: linear-gradient(90deg, #fb7185, #fbbf24);
    transition: width .12s linear;
}

/* Léptető sor */

.nav-rule {
    height: 1px;
    margin: 16px 0 14px;
    background: var(--line);
}

.counter {
    padding-top: .65rem;
    color: var(--muted);
    font: 13px var(--mono);
    text-align: center;
}

/* Technikai napló */

.terminal-window {
    display: flex;
    height: 640px;
    flex-direction: column;
    overflow: hidden;
    border: 1px solid var(--line);
    border-radius: 14px;
    background: var(--panel);
}

.terminal-topbar {
    display: flex;
    flex: 0 0 auto;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    border-bottom: 1px solid var(--line);
    color: var(--text);
    font-size: 13px;
}

.terminal-count {
    color: var(--dim);
    font: 11px var(--mono);
}

.terminal-body {
    display: flex;
    min-height: 0;
    flex: 1;
    flex-direction: column-reverse;
    overflow-y: auto;
    padding: 10px 14px;
    font: 12px/1.65 var(--mono);
    scrollbar-color: #314356 #0b121a;
}

.tl {
    display: grid;
    grid-template-columns: 62px 1fr;
    gap: 10px;
    padding: 1px 0;
}

.tl-time {
    color: var(--dim);
}

.tl-body {
    color: #c3cfdc;
    overflow-wrap: anywhere;
}

.tl-tag {
    margin-right: 6px;
    color: var(--muted);
}

.t-check { color: var(--cyan); }
.t-ok { color: var(--green); }
.t-err { color: var(--red); }
.t-warn { color: var(--amber); }
.t-att { color: var(--red); }

/* Animációk */

@keyframes send-to-cloud {
    0%   { left: 18%; opacity: 0; transform: scale(.75); }
    12%  { opacity: 1; transform: scale(1); }
    70%  { left: 50%; opacity: 1; }
    86%  { left: 50%; opacity: 0; }
    100% { left: 18%; opacity: 0; }
}

@keyframes send-to-device {
    0%   { left: 50%; opacity: 0; transform: scale(.75); }
    12%  { opacity: 1; transform: scale(1); }
    70%  { left: 82%; opacity: 1; }
    86%  { left: 82%; opacity: 0; }
    100% { left: 50%; opacity: 0; }
}

@keyframes attack-flight {
    0%   { left: 50%; top: 196px; opacity: 0; transform: scale(.7); }
    12%  { opacity: 1; transform: scale(1); }
    72%  { left: 78%; top: 130px; opacity: 1; }
    86%  { left: 78%; top: 130px; opacity: 0; transform: scale(.6); }
    100% { left: 50%; top: 196px; opacity: 0; }
}

@keyframes key-flight {
    0%   { left: 46%; top: 196px; opacity: 0; transform: scale(.7); }
    15%  { opacity: 1; transform: scale(1); }
    72%  { left: 78%; top: 130px; opacity: 1; }
    88%  { left: 78%; top: 130px; opacity: 0; transform: scale(.7); }
    100% { left: 46%; top: 196px; opacity: 0; }
}

@keyframes scan-device {
    from { left: 0; }
    to   { left: calc(100% - 2px); }
}

@keyframes package-ready {
    from { transform: scale(.9); }
    to   { transform: scale(1.08); }
}

@media (max-width: 900px) {
    .meta {
        justify-content: flex-start;
        padding-top: 0;
    }

    .terminal-window {
        height: 460px;
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
# Két azonos nevű kulcskép-készlet (-a / -b): a jelenetváltáskor a
# névváltás miatt az animáció újraindul, akkor is, ha a DOM-elem megmarad.
FX_TEMPLATE = """
@keyframes rise-§ {
    from { opacity: 0; transform: translateY(12px); }
    to   { opacity: 1; transform: none; }
}
@keyframes pop-§ {
    0%   { opacity: 0; transform: scale(.8); }
    60%  { opacity: 1; transform: scale(1.06); }
    100% { opacity: 1; transform: scale(1); }
}
@keyframes shake-§ {
    0%   { opacity: 0; transform: translateX(0); }
    15%  { opacity: 1; transform: translateX(-7px); }
    35%  { transform: translateX(6px); }
    55%  { transform: translateX(-4px); }
    75%  { transform: translateX(3px); }
    100% { opacity: 1; transform: none; }
}
@keyframes node-in-§ {
    from { transform: scale(.93); }
    to   { transform: scale(1); }
}

.fx-§ .scene-kicker  { animation: rise-§ .35s ease-out both; }
.fx-§ .scene-title   { animation: rise-§ .45s .06s ease-out both; }
.fx-§ .scene-action  { animation: rise-§ .50s .14s ease-out both; }
.fx-§ .scene-why     { animation: rise-§ .50s .26s ease-out both; }
.fx-§ .pkg-chip      { animation: rise-§ .40s ease-out both; }
.fx-§ .scene-outcome.good { animation: pop-§ .55s .40s cubic-bezier(.2, .9, .3, 1.2) both; }
.fx-§ .scene-outcome.bad  { animation: shake-§ .60s .40s ease-out both; }
.fx-§ .scene-node.active  {
    animation: node-in-§ .45s ease-out, breathe 3.2s .45s ease-in-out infinite;
}
"""

FX_STATIC = """
/* ---------- Közös kulcsképek ---------- */

@keyframes breathe {
    0%, 100% { box-shadow: 0 0 0 0 rgba(var(--glow), 0); }
    50%      { box-shadow: 0 0 26px 0 rgba(var(--glow), .22); }
}
@keyframes bob {
    0%, 100% { transform: translateY(0); }
    50%      { transform: translateY(-3px); }
}
@keyframes blink {
    0%, 100% { opacity: 1; }
    50%      { opacity: .2; }
}
@keyframes ring-out {
    from { opacity: .85; transform: scale(1); }
    to   { opacity: 0;   transform: scale(1.14); }
}
@keyframes impact {
    0%, 68% { opacity: 0;   transform: scale(1); }
    72%     { opacity: .95; transform: scale(1); }
    100%    { opacity: 0;   transform: scale(1.16); }
}

/* ---------- Fejléc, kártya, státusz ---------- */

@keyframes icon-glow {
    0%, 100% { box-shadow: 0 0 0 0 rgba(93, 214, 232, 0); }
    50%      { box-shadow: 0 0 20px 0 rgba(93, 214, 232, .28); }
}
.brand-icon { animation: icon-glow 3.6s ease-in-out infinite; }

@keyframes grid-drift { to { background-position: 28px 28px, 28px 28px; } }
.network-card {
    background-image:
        linear-gradient(rgba(93, 214, 232, .035) 1px, transparent 1px),
        linear-gradient(90deg, rgba(93, 214, 232, .035) 1px, transparent 1px);
    background-size: 28px 28px;
    animation: grid-drift 14s linear infinite;
}

.status-pill::before {
    display: inline-block;
    width: 6px;
    height: 6px;
    margin-right: 8px;
    vertical-align: middle;
    border-radius: 50%;
    background: currentColor;
    content: "";
    animation: blink 1.4s ease-in-out infinite;
}

/* ---------- Csomópontok színe ---------- */

.scene-node.factory { --glow: 93, 214, 232; }
.scene-node.cloud   { --glow: 167, 139, 250; }
.scene-node.device  { --glow: 74, 222, 155; }
.stage-bruteforce .scene-node.device,
.stage-bruteforce-success .scene-node.device,
.stage-error .scene-node.device { --glow: 251, 113, 133; }

.scene-node.active .scene-ic { animation: bob 3s ease-in-out infinite; }

/* ---------- Útvonal és csomag ---------- */

.network-route::after {
    position: absolute;
    top: -1px;
    left: 0;
    width: 70px;
    height: 3px;
    border-radius: 3px;
    background: linear-gradient(90deg, transparent, var(--cyan), transparent);
    content: "";
    opacity: 0;
}
@keyframes route-a {
    0%   { left: 0; opacity: 0; }
    15%  { opacity: 1; }
    80%  { opacity: 1; }
    100% { left: calc(50% - 70px); opacity: 0; }
}
@keyframes route-b {
    0%   { left: 50%; opacity: 0; }
    15%  { opacity: 1; }
    80%  { opacity: 1; }
    100% { left: calc(100% - 70px); opacity: 0; }
}
.stage-uploading .network-route::after   { animation: route-a 2.4s ease-in-out infinite; }
.stage-downloading .network-route::after { animation: route-b 2.4s ease-in-out infinite; }

.moving-package { box-shadow: 0 0 16px rgba(93, 214, 232, .35); }
.stage-uploading .moving-package::before,
.stage-downloading .moving-package::before {
    position: absolute;
    top: 50%;
    right: 100%;
    width: 46px;
    height: 2px;
    margin-right: 4px;
    background: linear-gradient(90deg, transparent, rgba(93, 214, 232, .85));
    content: "";
}

/* ---------- Gyártói lépések ---------- */

@keyframes build-bar {
    0%   { transform: scaleX(0); opacity: 1; }
    85%  { transform: scaleX(1); opacity: 1; }
    100% { transform: scaleX(1); opacity: 0; }
}
.stage-factory .scene-node.factory::before {
    position: absolute;
    right: 14px;
    bottom: 9px;
    left: 14px;
    height: 3px;
    border-radius: 3px;
    background: var(--cyan);
    box-shadow: 0 0 10px var(--cyan);
    content: "";
    transform-origin: left;
    animation: build-bar 2.2s ease-in-out infinite;
}

@keyframes key-turn {
    0%, 100% { transform: rotate(-18deg); }
    50%      { transform: rotate(22deg); }
}
.stage-keys .scene-node.factory .scene-ic .ic {
    animation: key-turn 1.8s ease-in-out infinite;
}

.stage-signing .scene-node.factory::after {
    position: absolute;
    inset: -1px;
    border: 2px solid var(--cyan);
    border-radius: 14px;
    content: "";
    animation: ring-out 1.6s ease-out infinite;
}

/* ---------- Csomag-címke ---------- */

@keyframes shimmer {
    from { background-position: -140px 0; }
    to   { background-position: 140px 0; }
}
.pkg-chip.signing {
    background-image: linear-gradient(
        100deg, transparent 30%, rgba(93, 214, 232, .18) 50%, transparent 70%
    );
    background-repeat: no-repeat;
    background-size: 120px 100%;
    animation: shimmer 1.4s linear infinite;
}
.dots i {
    display: inline-block;
    width: 4px;
    height: 4px;
    margin-left: 3px;
    border-radius: 50%;
    background: currentColor;
    animation: blink 1.1s ease-in-out infinite;
}
.dots i:nth-child(2) { animation-delay: .18s; }
.dots i:nth-child(3) { animation-delay: .36s; }

@keyframes stamp {
    from { opacity: 0; transform: scale(2.2) rotate(-25deg); }
    to   { opacity: 1; transform: none; }
}
.pkg-state .ic { animation: stamp .45s cubic-bezier(.2, .9, .3, 1.2) both; }

/* ---------- Ellenőrzés, elfogadás, elutasítás ---------- */

@keyframes device-reject {
    0%, 100% { transform: translateX(0); }
    15%      { transform: translateX(-8px); }
    35%      { transform: translateX(7px); }
    55%      { transform: translateX(-5px); }
    75%      { transform: translateX(3px); }
}
.stage-checking.out-bad .scene-node.device.active,
.stage-error .scene-node.device {
    border-color: rgba(251, 113, 133, .7);
    animation: device-reject .6s ease-out 1;
}
.stage-accepted .scene-node.device::after {
    position: absolute;
    inset: -2px;
    border: 2px solid var(--green);
    border-radius: 16px;
    content: "";
    animation: ring-out 1.4s ease-out infinite;
}

/* ---------- Támadó ---------- */

@keyframes figure-bob {
    0%, 100% { transform: translateX(-50%) translateY(0); }
    50%      { transform: translateX(-50%) translateY(-4px); }
}
@keyframes wiggle {
    0%, 100% { transform: rotate(0); }
    25%      { transform: rotate(-14deg); }
    75%      { transform: rotate(14deg); }
}
.attacker-figure { animation: figure-bob 1.6s ease-in-out infinite; }
.attacker-figure .ic { animation: wiggle .7s ease-in-out infinite; }

.stage-attacker .scene-node.device::after,
.stage-bruteforce .scene-node.device::after {
    position: absolute;
    inset: -2px;
    border: 2px solid var(--green);
    border-radius: 16px;
    content: "";
    opacity: 0;
}
.stage-attacker .scene-node.device::after   { animation: impact 1.8s ease-out infinite; }
.stage-bruteforce .scene-node.device::after {
    border-color: var(--red);
    animation: impact 1.4s ease-out infinite;
}
.stage-attacker.out-bad .scene-node.device::after { border-color: var(--red); }

/* ---------- Jelszópróba ---------- */

@keyframes jiggle {
    0%, 100% { transform: rotate(0) translateX(0); }
    25%      { transform: rotate(-9deg) translateX(-2px); }
    75%      { transform: rotate(9deg) translateX(2px); }
}
@keyframes alarm {
    from { box-shadow: 0 0 0 0 rgba(251, 113, 133, .0); border-color: rgba(251, 113, 133, .4); }
    to   { box-shadow: 0 0 34px 2px rgba(251, 113, 133, .45); border-color: rgba(251, 113, 133, .95); }
}
.stage-bruteforce .scene-node.device.active .scene-ic {
    animation: jiggle .45s ease-in-out infinite;
}
.stage-bruteforce-success .scene-node.device.active {
    animation: alarm .55s ease-in-out infinite alternate;
}
.stage-bruteforce-failed .scene-node.device.active {
    border-color: rgba(74, 222, 155, .6);
    --glow: 74, 222, 155;
}
.stage-bruteforce-failed .scene-node.device.active .scene-ic {
    background: rgba(74, 222, 155, .12);
    color: var(--green);
}

@keyframes live-pulse {
    0%, 100% { border-color: rgba(251, 113, 133, .25); }
    50%      { border-color: rgba(251, 113, 133, .7); }
}
@keyframes stripes { to { background-position: 17px 0, 0 0; } }
.live-guess { animation: live-pulse 1.2s ease-in-out infinite; }
.live-guess-label::before {
    display: inline-block;
    width: 7px;
    height: 7px;
    margin-right: 8px;
    border-radius: 50%;
    background: var(--red);
    content: "";
    animation: blink 1s ease-in-out infinite;
}
.live-guess-value::after {
    margin-left: 3px;
    color: var(--red);
    content: "▍";
    animation: blink 1s steps(1) infinite;
}
.guess-progress span {
    background:
        repeating-linear-gradient(
            45deg, rgba(255, 255, 255, .22) 0 6px, transparent 6px 12px
        ),
        linear-gradient(90deg, #fb7185, #fbbf24);
    background-size: 17px 17px, 100% 100%;
    animation: stripes .6s linear infinite;
}

/* ---------- Lépéslista ---------- */

@keyframes dot-pulse {
    0%        { box-shadow: 0 0 0 0 rgba(93, 214, 232, .55); }
    70%, 100% { box-shadow: 0 0 0 9px rgba(93, 214, 232, 0); }
}
@keyframes draw-check {
    from { stroke-dashoffset: 24; }
    to   { stroke-dashoffset: 0; }
}
@keyframes line-grow {
    from { transform: scaleY(0); }
    to   { transform: scaleY(1); }
}
@keyframes seg-fill {
    from { transform: scaleX(0); }
    to   { transform: scaleX(1); }
}
@keyframes label-in {
    from { opacity: 0; transform: translateX(-8px); }
    to   { opacity: 1; transform: none; }
}
.step.active .step-dot   { animation: dot-pulse 1.8s ease-out infinite; }
.step.active .step-label { animation: label-in .4s ease-out both; }
.step.done .step-dot .ic path {
    stroke-dasharray: 24;
    animation: draw-check .5s ease-out both;
}
.step.done:not(.last)::before {
    transform-origin: top;
    animation: line-grow .5s ease-out both;
}
.step-segs span { transform-origin: left; }
.step-segs span.on { animation: seg-fill .4s ease-out both; }

/* ---------- Napló ---------- */

@keyframes line-in {
    from { opacity: 0; transform: translateY(6px); background: rgba(93, 214, 232, .14); }
    to   { opacity: 1; transform: none; background: transparent; }
}
.terminal-body .tl:first-child { animation: line-in .45s ease-out; }
.terminal-topbar > span:first-child::before {
    display: inline-block;
    width: 7px;
    height: 7px;
    margin-right: 9px;
    border-radius: 50%;
    background: var(--green);
    content: "";
    animation: blink 1.6s ease-in-out infinite;
}

/* ---------- Gombok ---------- */

.stButton > button,
[data-testid="stFormSubmitButton"] button {
    transition: transform .15s ease, border-color .15s ease,
                color .15s ease, background .15s ease;
}
.stButton > button:hover:not(:disabled),
[data-testid="stFormSubmitButton"] button:hover:not(:disabled) {
    transform: translateY(-1px);
}
.stButton > button:active:not(:disabled),
[data-testid="stFormSubmitButton"] button:active:not(:disabled) {
    transform: scale(.97);
}
@keyframes nudge {
    0%, 100% { box-shadow: 0 0 0 0 rgba(93, 214, 232, .45); }
    60%      { box-shadow: 0 0 0 10px rgba(93, 214, 232, 0); }
}
.st-key-scene_next button:not(:disabled) { animation: nudge 2s ease-out infinite; }

/* ---------- Kevesebb mozgás ---------- */

@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
        animation-duration: .01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: .01ms !important;
    }
}
"""

APP_CSS += FX_STATIC + "".join(FX_TEMPLATE.replace("§", s) for s in "ab")


FINALE_CSS = """
.finale {
    position: fixed;
    inset: 0;
    z-index: 999990;
    display: grid;
    place-items: center;
    overflow: hidden;
    background: radial-gradient(ellipse at 50% 40%, #0f2a36 0%, #070c12 62%);
    animation: finale-fade .8s ease-out both;
}
@keyframes finale-fade { from { opacity: 0; } to { opacity: 1; } }

/* mozgó rács */
.finale-grid {
    position: absolute;
    inset: -56px;
    background-image:
        linear-gradient(rgba(93, 214, 232, .07) 1px, transparent 1px),
        linear-gradient(90deg, rgba(93, 214, 232, .07) 1px, transparent 1px);
    background-size: 56px 56px;
    -webkit-mask-image: radial-gradient(circle at 50% 50%, #000 0%, transparent 70%);
    mask-image: radial-gradient(circle at 50% 50%, #000 0%, transparent 70%);
    animation: finale-grid 10s linear infinite;
}
@keyframes finale-grid { to { transform: translate(56px, 56px); } }

/* felfelé szálló fénypontok */
.finale-particles i {
    position: absolute;
    bottom: -12px;
    left: var(--x);
    width: var(--z);
    height: var(--z);
    border-radius: 50%;
    background: var(--cyan);
    box-shadow: 0 0 10px var(--cyan);
    opacity: 0;
    animation: finale-rise var(--d) var(--s) linear infinite;
}
.finale-particles i:nth-child(3n)   { background: var(--green); box-shadow: 0 0 10px var(--green); }
.finale-particles i:nth-child(3n+1) { background: #a78bfa;      box-shadow: 0 0 10px #a78bfa; }
@keyframes finale-rise {
    0%   { opacity: 0;  transform: translateY(0); }
    10%  { opacity: .8; }
    90%  { opacity: .5; }
    100% { opacity: 0;  transform: translateY(-110vh); }
}

.finale-core {
    position: relative;
    z-index: 2;
    padding: 0 1.5rem;
    text-align: center;
}

/* pajzs-ikon gyűrűkkel */
.finale-badge {
    position: relative;
    display: grid;
    width: 112px;
    height: 112px;
    margin: 0 auto 34px;
    place-items: center;
    border: 1px solid rgba(93, 214, 232, .5);
    border-radius: 30px;
    background: #0e2830;
    color: var(--cyan);
    animation:
        finale-badge-in .9s .2s cubic-bezier(.2, .9, .3, 1.25) both,
        icon-glow 3.6s 1.2s ease-in-out infinite;
}
@keyframes finale-badge-in {
    from { opacity: 0; transform: scale(.3) rotate(-25deg); }
    to   { opacity: 1; transform: none; }
}
.finale-ring {
    position: absolute;
    inset: -1px;
    border: 2px solid var(--cyan);
    border-radius: 30px;
    opacity: 0;
    animation: finale-ring 2.8s 1.1s ease-out infinite;
}
.finale-ring.r2 { animation-delay: 2.5s; }
@keyframes finale-ring {
    from { opacity: .7; transform: scale(1); }
    to   { opacity: 0;  transform: scale(1.9); }
}

/* cím: szavanként élesedik be, utána fénycsík fut át rajta */
.finale-title {
    font-size: clamp(2.4rem, 6vw, 5rem);
    font-weight: 800;
    letter-spacing: -.03em;
    line-height: 1.1;
}
.finale-title span {
    display: inline-block;
    margin: 0 .14em;
    background: linear-gradient(100deg, #fff 0%, var(--cyan) 50%, #fff 100%);
    background-size: 200% 100%;
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
    animation:
        finale-word .8s calc(.7s + var(--i) * .16s) ease-out both,
        finale-shine 5s 2.4s linear infinite;
}
@keyframes finale-word {
    from { opacity: 0; transform: translateY(28px); filter: blur(12px); }
    to   { opacity: 1; transform: none;             filter: blur(0); }
}
@keyframes finale-shine { to { background-position: 200% 0; } }

.finale-rule {
    width: 0;
    height: 2px;
    margin: 34px auto 26px;
    background: linear-gradient(90deg, transparent, var(--cyan), transparent);
    animation: finale-rule 1s 1.6s ease-out forwards;
}
@keyframes finale-rule { to { width: min(360px, 60vw); } }

.finale-by {
    color: var(--muted);
    font: 13px var(--mono);
    letter-spacing: .28em;
    text-transform: uppercase;
    animation: finale-up .6s 2s ease-out both;
}
@keyframes finale-up {
    from { opacity: 0; transform: translateY(12px); }
    to   { opacity: 1; transform: none; }
}

/* név: betűnként érkezik */
.finale-name {
    margin-top: 12px;
    color: #fff;
    font-size: clamp(1.5rem, 3.2vw, 2.4rem);
    font-weight: 700;
    letter-spacing: .01em;
    animation: finale-glow 3s 4.5s ease-in-out infinite;
}
.finale-name span {
    display: inline-block;
    animation: finale-letter .5s calc(2.3s + var(--i) * .05s) ease-out both;
}
@keyframes finale-letter {
    from { opacity: 0; transform: translateY(14px) scale(.8); }
    to   { opacity: 1; transform: none; }
}
@keyframes finale-glow {
    0%, 100% { text-shadow: 0 0 0 rgba(93, 214, 232, 0); }
    50%      { text-shadow: 0 0 22px rgba(93, 214, 232, .6); }
}

/* halvány "Vissza" gomb a képernyő alján */
.st-key-finale_back {
    position: fixed;
    bottom: 22px;
    left: 50%;
    z-index: 999999;
    width: auto !important;
    transform: translateX(-50%);
    opacity: .35;
    transition: opacity .2s ease;
}
.st-key-finale_back:hover { opacity: 1; }
.st-key-finale_back button {
    min-height: 2.2rem;
    color: var(--muted);
    font-size: 13px;
    animation: finale-up .6s 4s ease-out both;
}
"""

APP_CSS += FINALE_CSS


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


STAGE_LABELS = {
    "idle": "Várakozik",
    "factory": "Build",
    "keys": "Aláírókulcs",
    "signing": "Aláírás",
    "delivery": "Közzététel",
    "uploading": "Letöltés",
    "downloading": "Bootloader",
    "checking": "Ellenőrzés",
    "accepted": "Telepítés",
    "attacker": "Támadási próba",
    "bruteforce": "Jelszópróba",
    "bruteforce-success": "Találat",
    "bruteforce-failed": "Próba kész",
    "done": "Összesítés",
    "error": "Hiba",
}

DEFAULT_ACTIONS = {
    "idle": "Add meg a kész firmware-fájlt és az aláírókulcs jelszavát.",
    "factory": "A kiadási folyamat kész firmware-binárist ad át; a program beolvassa a fájl bájtjait.",
    "keys": "A kiadási rendszer előkészíti a privát aláírókulcsot és a hozzá tartozó publikus kulcsot.",
    "signing": "A csomagkészítő manifestet állít elő, lenyomatot számít, majd aláírja a manifestet.",
    "delivery": "A program az aláírt csomagot az out/ mappába menti.",
    "uploading": (
        "Üzemi rendszerben a kiadási szolgáltatás a verziózott csomagot HTTPS-en "
        "közzéteszi a frissítési tárhelyen. Ez a program nem küld HTTP-kérést."
    ),
    "downloading": (
        "Üzemi rendszerben az eszköz frissítési kliense HTTPS-en tölti le a neki szánt "
        "csomagot. Ez a program nem végez hálózati letöltést."
    ),
    "checking": "Az ellenőrző megvizsgálja a csomag aláírását, felépítését, célmodelljét, fájladatait és verzióját.",
    "accepted": "Az ellenőrzés sikeres; a demó frissíti az eszköz helyi verzióállapotát.",
    "attacker": "Az eszköz ellenőrzési eljárása megvizsgálja a módosított tesztcsomagokat.",
    "bruteforce": "A jelszópróba kizárólag a helyi keys/private.json fájlt vizsgálja.",
    "bruteforce-success": "Az egyik kipróbált jelölt megnyitotta a helyi privát kulcsot.",
    "bruteforce-failed": "A kipróbált jelöltek közül egyik sem nyitotta meg a helyi privát kulcsot.",
    "done": "A bemutató összesíti az ellenőrzési eredményeket.",
    "error": "A folyamat hiba miatt leállt.",
}


def draw_story(placeholder, story: dict[str, Any], fx: int = 0) -> None:
    """Megjeleníti a gyártó → internet → eszköz jelenetet és a hozzá tartozó szöveget."""

    if not isinstance(story, dict):
        story = {}

    stage = story.get("stage", "idle")
    if not isinstance(stage, str) or stage not in STAGE_LABELS:
        stage = "idle"

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
    bad_stage = stage in {"attacker", "error"} or is_bruteforce

    # --- Szöveg ------------------------------------------------------

    raw_action = story.get("what")
    has_custom_action = raw_action is not None and bool(str(raw_action).strip())
    action = (
        plain_text(raw_action, DEFAULT_ACTIONS[stage], limit=1200)
        or DEFAULT_ACTIONS[stage]
    )

    who = plain_text(story.get("who"), "", 60)
    where = plain_text(story.get("where"), "", 80)
    actor_to_highlight = who

    # A szereplő az eseménymondat alanya lesz ("Az eszköz ...").
    # Üres "who" esetén a "what" teljes mondat.
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
        actor_style = "color:#fda4af;font-weight:700;"
    elif who.casefold() in {"eszköz", "device"}:
        actor_style = "color:#4ade9b;font-weight:700;"
    else:
        actor_style = "color:#5dd6e8;font-weight:700;"

    phrases = [
        (actor_to_highlight, actor_style),
        (where, "color:#fbbf24;font-weight:700;"),
    ]
    if stage == "attacker":
        phrases.append(("az eszköz", "color:#4ade9b;font-weight:700;"))

    action_markup = highlight_phrases(action, phrases)

    step = int(story.get("step") or 0)
    kicker = plain_text(story.get("kicker"), "", 60) or STEP_GROUP_OF.get(step, "")
    title = plain_text(story.get("title"), "Firmware-frissítés", 100)

    why_markup = ""
    why = plain_text(story.get("why"), "", limit=700)
    if why:
        why_markup = (
            '<div class="scene-why">'
            '<div class="scene-why-label">Miért fontos?</div>'
            f'<div class="scene-why-text">{html.escape(ensure_period(why))}</div>'
            "</div>"
        )

    outcome_markup = ""
    outcome_state = ""
    outcome = story.get("outcome")
    if outcome:
        ok = bool(story.get("outcome_ok", True))
        outcome_state = "out-good" if ok else "out-bad"
        outcome_markup = (
            f'<div class="scene-outcome {"good" if ok else "bad"}">'
            f'{icon("check-circle" if ok else "x-circle", 18)}'
            f'<span>{html.escape(plain_text(outcome, "", 180))}</span>'
            "</div>"
        )

    # --- Jelenet -----------------------------------------------------

    def node(kind: str, glyph: str, name: str, caption: str, active: bool) -> str:
        return (
            f'<div class="scene-node {kind}{" active" if active else ""}">'
            f'<span class="scene-ic">{icon(glyph, 22)}</span>'
            f"<strong>{html.escape(name)}</strong>"
            f"<small>{html.escape(caption)}</small>"
            "</div>"
        )

    if is_bruteforce:
        device_node = node("device", "key", "Privát kulcs", "jelszóval védett", device_active)
    else:
        device_node = node("device", "chip", "Eszköz", "letölt · ellenőriz", device_active)

    chip_state = ""
    chip_class = ""
    if stage == "signing":
        chip_state = '<span class="pkg-state">aláírás<span class="dots"><i></i><i></i><i></i></span></span>'
        chip_class = " signing"
    elif stage in {
        "delivery",
        "uploading",
        "downloading",
        "checking",
        "accepted",
    }:
        chip_state = f'<span class="pkg-state">{icon("check", 13)}aláírva</span>'
    elif stage == "attacker":
        chip_state = '<span class="pkg-state bad">módosított</span>'
    elif stage == "error":
        chip_state = '<span class="pkg-state bad">elutasítva</span>'

    chip_markup = (
        f'<div class="pkg-chip{chip_class}">{icon("box", 15)}<b>csomag</b>{chip_state}</div>'
        if chip_state
        else ""
    )

    packet_icon = "key" if is_bruteforce else "box"

    scene_markup = (
        f'<div class="storyboard stage-{stage} fx-{fx % 2} {outcome_state}">'
        '<div class="network-card">'
        '<div class="network-head">'
        "<span>Gyártó → internet → eszköz</span>"
        f'<span class="status-pill{" bad" if bad_stage else ""}">'
        f"{html.escape(STAGE_LABELS[stage])}</span>"
        "</div>"
        '<div class="network-scene">'
        f"{chip_markup}"
        '<div class="network-route"></div>'
        f'{node("factory", "factory", "Gyártó", "készít · aláír", factory_active)}'
        f'{node("cloud", "cloud", "Internet", "frissítési szerver", cloud_active)}'
        f"{device_node}"
        f'<div class="moving-package">{icon("box", 18)}</div>'
        f'<div class="attacker-figure">{icon("bug", 15)}<span>TÁMADÓ</span></div>'
        f'<div class="attack-packet">{icon(packet_icon, 18)}</div>'
        "</div>"
        "</div>"
        '<div class="scene-copy">'
        f'<div class="scene-kicker">{html.escape(kicker)}</div>'
        f'<div class="scene-title">{html.escape(title)}</div>'
        f'<div class="scene-action">{action_markup}</div>'
        f"{why_markup}"
        f"{outcome_markup}"
        "</div>"
        "</div>"
    )

    placeholder.markdown(scene_markup, unsafe_allow_html=True)


def draw_stepper(placeholder, current: dict[str, Any] | None) -> None:
    """A bal oldali lépéslista; az aktuális jelenethez igazodik."""

    current_step = int(current.get("step") or 0) if current else 0
    sub = int(current.get("sub") or 0) if current else 0
    sub_total = int(current.get("sub_total") or 0) if current else 0

    parts = ['<div class="stepper">']

    for group, items in STEP_GROUPS:
        parts.append(f'<div class="step-group">{html.escape(group)}</div>')

        for position, (number, label) in enumerate(items):
            if number < current_step:
                state = "done"
            elif number == current_step:
                state = "active"
            else:
                state = "pending"

            last = " last" if position == len(items) - 1 else ""
            dot = icon("check", 13) if state == "done" else str(number)

            segments = ""
            if state == "active" and sub_total:
                segments = (
                    '<div class="step-segs">'
                    + "".join(
                        f'<span class="{"on" if index < sub else ""}"></span>'
                        for index in range(sub_total)
                    )
                    + "</div>"
                )

            parts.append(
                f'<div class="step {state}{last}">'
                '<div class="step-row">'
                f'<span class="step-dot">{dot}</span>'
                f'<span class="step-label">{html.escape(label)}</span>'
                "</div>"
                f"{segments}"
                "</div>"
            )

    parts.append("</div>")
    placeholder.markdown("".join(parts), unsafe_allow_html=True)


# ---------------------------------------------------------------------
# Technikai terminálnapló
# ---------------------------------------------------------------------

LOG_LINE = re.compile(r"^(\d\d:\d\d:\d\d)\s+(?:\[([^\]]+)\]\s*)?(.*)$", re.S)

TAG_CLASSES = {
    "ellenőrzés": "t-check",
    "ok": "t-ok",
    "kész": "t-ok",
    "találat": "t-ok",
    "hiba": "t-err",
    "fail": "t-err",
    "figyelem": "t-warn",
    "warn": "t-warn",
    "támadó": "t-att",
    "audit": "t-att",
}


class Terminal:
    """A technikai eseményeket a jelenet mellett, külön panelben mutatja."""

    def __init__(self, placeholder):
        self.placeholder = placeholder
        saved = st.session_state.get("terminal_lines")

        if isinstance(saved, list):
            self.lines = list(saved)
        else:
            self.lines = []
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
            match = LOG_LINE.match(line)
            if match:
                stamp, tag, body = match.groups()
            else:
                stamp, tag, body = "", None, line

            tag_markup = ""
            if tag:
                tag_class = TAG_CLASSES.get(tag.casefold(), "")
                tag_markup = (
                    f'<span class="tl-tag {tag_class}">'
                    f"{html.escape(tag.casefold())}</span>"
                )

            rendered.append(
                '<div class="tl">'
                f'<span class="tl-time">{html.escape(stamp)}</span>'
                f'<span class="tl-body">{tag_markup}{html.escape(body)}</span>'
                "</div>"
            )

        if not rendered:
            rendered.append(
                '<div class="tl"><span class="tl-time"></span>'
                '<span class="tl-body">A napló üres.</span></div>'
            )

        markup = (
            '<div class="terminal-window">'
            '<div class="terminal-topbar">'
            "<span>Technikai napló</span>"
            f'<span class="terminal-count">{len(self.lines)} sor</span>'
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


def read_wordlist_head(
    path: Path,
    limit: int,
    log: Callable[[str], None],
) -> tuple[list[str], bool]:
    """A szólista első `limit` nem üres sorát adja vissza; a második érték jelzi, ha maradt le."""

    candidates: list[str] = []

    if not path.is_file():
        log(f"[FIGYELEM] Nem található a jelszólista: {path}")
        return candidates, False

    try:
        with path.open("r", encoding="utf-8-sig", newline="") as file:
            for line in file:
                candidate = line.rstrip("\r\n")
                if candidate == "":
                    continue

                if len(candidates) >= limit:
                    return candidates, True

                candidates.append(candidate)
    except (OSError, UnicodeError) as exc:
        log(f"[FIGYELEM] A jelszavak.txt nem olvasható: {exc}")

    return candidates, False

def run_automatic_password_attack(
    log: Callable[[str], None],
    show_guess: Callable[..., None],
    wordlist_path: Path | str | None = None,
) -> dict[str, Any]:
    """A jelszavak.txt első sorait (összesen legfeljebb 200 jelöltet) próbálja a helyi kulcson."""

    private_path = KEYS / "private.json"

    def empty_result() -> dict[str, Any]:
        return {
            "found": False,
            "skipped": True,
            "attempts": 0,
            "password": None,
            "wordlist_attempts": 0,
            "extra_attempts": 0,
        }

    if not private_path.is_file():
        log("[FIGYELEM] Nincs helyi privát kulcs; a jelszópróba kimarad.")
        return empty_result()

    path = PASSWORD_LIST if wordlist_path is None else Path(wordlist_path)

    wordlist, cut_off = read_wordlist_head(
        path,
        AUTO_ATTACK_MAX_GUESSES,
        log,
    )

    # A maradék helyet kiegészítő jelöltek töltik ki (a szólistában
    # már szereplőket kihagyjuk).
    already = set(wordlist)
    extra_guesses = list(
        islice(
            (c for c in automatic_guess_stream() if c not in already),
            AUTO_ATTACK_MAX_GUESSES - len(wordlist),
        )
    )
    total = len(wordlist) + len(extra_guesses)

    if total == 0:
        log("[FIGYELEM] Nincs kipróbálható jelszójelölt.")
        return empty_result()

    log(
        f"[INFO] Helyi kulcspróba: legfeljebb {AUTO_ATTACK_MAX_GUESSES} jelölt "
        f"({len(wordlist)} szólista-jelölt, {len(extra_guesses)} kiegészítő)."
    )
    if cut_off:
        log(
            f"[INFO] A jelszavak.txt további sorai kimaradnak, "
            f"csak az első {AUTO_ATTACK_MAX_GUESSES} számít."
        )

    started = time.perf_counter()
    attempts = 0

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

    def found_result(candidate: str, wordlist_n: int, extra_n: int) -> dict[str, Any]:
        log(f"[TALÁLAT] A helyi kulcs jelszava: {candidate!r}")
        return {
            "found": True,
            "skipped": False,
            "attempts": attempts,
            "password": candidate,
            "wordlist_attempts": wordlist_n,
            "extra_attempts": extra_n,
            "seconds": time.perf_counter() - started,
        }

    wordlist_attempts = 0
    for candidate in wordlist:
        wordlist_attempts += 1
        if try_candidate(candidate, "Szólista-próba"):
            return found_result(candidate, wordlist_attempts, 0)

    log(
        f"[INFO] A szólista próbája befejeződött: "
        f"{wordlist_attempts} jelölt."
    )

    extra_attempts = 0
    for candidate in extra_guesses:
        extra_attempts += 1
        if try_candidate(candidate, "Kiegészítő jelszópróba"):
            return found_result(candidate, wordlist_attempts, extra_attempts)

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
    why: str = "",
    outcome: str = "",
    outcome_ok: bool = True,
    step: int = 0,
    kicker: str = "",
    sub: int = 0,
    sub_total: int = 0,
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
        "step": step,
        "kicker": kicker,
        "sub": sub,
        "sub_total": sub_total,
    }


def run_pipeline(
    firmware: bytes,
    password: str,
    filename: str,
    log: Callable[[str], None],
    show_guess: Callable[..., None],
    meta: dict[str, Any],
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
        title="Firmware-build és tesztelés",
        step=1,
        who="Gyártóvállalat",
        what=(
            "a forráskódból lefordítja a firmware-t, lefuttatja a teszteket, "
            "és reprodukálható bináris fájlt állít elő. "
            f"A kiadási artefaktum most a {filename} fájl ({len(firmware)} bájt)."
        ),
        where=filename,
        why=(
            "Csak tesztelt, reprodukálható build kerülhet aláírásra és kiadásra, "
            "így a kiadott kód visszavezethető a forráskódra."
        ),
    )

    # 2. Kiadói aláírókulcs.
    yield scene(
        stage="keys",
        title="Kiadói aláírókulcs",
        step=2,
        who="Gyártóvállalat",
        what=(
            "a privát aláírókulcsot HSM-ben vagy kulcskezelő szolgáltatásban tartja, "
            "onnan az nem kerülhet ki. Aláírást csak a kiadási szerver kérhet, "
            "emberi jóváhagyással vagy többes aláírással."
        ),
        where="HSM",
        why=(
            "Ha a privát kulcs kiszivárog, a támadó bármilyen hamis firmware-t "
            "el tudna látni érvényes gyártói aláírással, ezért a kulcsot "
            "a lehető legszigorúbban kell védeni."
        ),
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
        title="Manifest és digitális aláírás",
        step=3,
        who="Gyártóvállalat",
        what=(
            "manifestet állít elő a célmodellel, a verzióval, a kiadás dátumával "
            "és a firmware SHA-256-lenyomatával, majd a privát kulccsal aláírja."
        ),
        where="manifest",
        why=(
            "Az aláírás hitelesíti a manifest tartalmát, és ahhoz köti a firmware-t. "
            "A firmware-t nem titkosítja."
        ),
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

    # 4. Közzététel a frissítési szolgáltatásban.
    yield scene(
        stage="delivery",
        title="Közzététel a frissítési szolgáltatásban",
        step=4,
        who="Gyártóvállalat",
        what=(
            "a verziózott, aláírt csomagot HTTPS-en közzéteszi a frissítési tárhelyen "
            "vagy CDN-en. A kiadás fokozatos (staged rollout): először egy kis "
            "tesztcsoport, azután a többi eszköz kapja meg."
        ),
        where="frissítési tárhely",
        why=(
            "A fokozatos kiadás korlátozza a hibás frissítés hatását, "
            "és probléma esetén leállítható."
        ),
    )

    write_bundle(bundle, OUT)
    trusted_public_key = load_public_key(KEYS / "public.hex")
    log("[OK] A csomag elmentve az out/ mappába.")

    # 5. Letöltés az eszközön.
    yield scene(
        stage="uploading",
        title="Csomag letöltése az eszközön",
        step=5,
        who="Eszköz",
        what=(
            "frissítési kliense lekérdezi, van-e frissítés a modelljéhez, majd "
            "HTTPS-en letölti a csomagot. Részlegesen letöltött csomagot nem telepít."
        ),
        where="frissítési szolgáltatás",
        why=(
            "A TLS védi az átvitelt, de a végső bizalmat a csomag aláírásának "
            "ellenőrzése adja, nem a csatorna."
        ),
    )
    log("[INFO] A csomag az eszköz oldalán ellenőrzésre kész.")

    # 6. Bootloader-ellenőrzés az eszközön.
    yield scene(
        stage="downloading",
        title="Bootloader-ellenőrzés",
        step=6,
        who="Eszköz",
        what=(
            "bootloadere a gyártáskor beégetett publikus kulcs segítségével "
            "ellenőrzi a manifest aláírását, majd a modellazonosítót, a verziót, "
            "a firmware méretét és SHA-256-lenyomatát."
        ),
        where="beégetett publikus kulcs",
        why=(
            "A publikus kulcsot gyártáskor kell az eszközbe írni, és nem szabad "
            "a letöltött csomagból átvenni: különben bármely támadó a saját "
            "kulcsát adhatná meg."
        ),
    )

    # 7. Csomagellenőrzés.
    yield scene(
        stage="checking",
        title="Csomagellenőrzés",
        step=7,
        sub=0,
        sub_total=5,
        who="Eszköz",
        what=(
            "ellenőrzi az aláírást, a csomag felépítését, a modellazonosítót, "
            "a firmware méretét és SHA-256-lenyomatát, valamint a verziót. "
            "A verziónak nagyobbnak kell lennie a jelenleg telepítettnél "
            "(visszalépés elleni védelem)."
        ),
        where="",
        why=(
            "A visszalépés elleni védelem megakadályozza, hogy egy régi, sebezhető "
            "firmware visszakerüljön az eszközre, még érvényes aláírás esetén is."
        ),
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

    # A léptető teljes lépésszáma a nyomvonal hosszától függ.
    meta["total"] = 17 + len(result["trace"])

    log_trace(result["trace"], log)

    # Az ellenőrzési lépések részletes megjelenítése.
    for step in result["trace"]:
        index = int(get_field(step, "index", 0))
        passed = bool(get_field(step, "passed", False))

        description = VERIFY_EXPLANATIONS.get(
            index,
            {
                "title": f"{index}/5 — Ellenőrzés",
                "what": "ellenőriz egy csomagadatot.",
                "why": "Az ellenőrzési nyomvonal rögzíti az eredményt.",
            },
        )

        yield scene(
            stage="checking",
            title=description["title"].split("—", 1)[-1].strip(),
            kicker=f"Ellenőrzés {index}/5",
            step=7,
            sub=index,
            sub_total=5,
            who="Eszköz",
            what=description["what"],
            where="",
            why=description["why"],
            outcome=(
                "Az ellenőrzés sikeres."
                if passed
                else "Az ellenőrzés sikertelen."
            ),
            outcome_ok=passed,
        )

    result["after"] = read_installed_version(STATE)
    log(f"[INFO] Helyi verzió előtte: {result['before']}.")
    log(f"[INFO] Helyi verzió utána: {result['after']}.")

    # 8. Telepítés A/B partícióra.
    if result["error"] is None:
        yield scene(
            stage="accepted",
            title="Telepítés az inaktív partícióra",
            step=8,
            who="Eszköz",
            what=(
                "a sikeresen ellenőrzött firmware-képet az inaktív partícióra írja, "
                "újraindul, és az új firmware-t próbaként indítja."
            ),
            where="inaktív A/B partíció",
            why=(
                "Ha az új firmware nem indul el megfelelően, az eszköz automatikusan "
                "visszavált a korábbi, működő partícióra."
            ),
            outcome="Az ellenőrzés sikeres, a telepítés elindulhat.",
            outcome_ok=True,
        )
    else:
        yield scene(
            stage="error",
            title="Az ellenőrzés sikertelen, a csomag elutasítva",
            step=8,
            who="",
            what=result["error_text"] or "Az ellenőrző elutasította a csomagot.",
            where="",
            why="Elutasított csomag esetén a jelenlegi firmware marad érvényben.",
            outcome="A telepítés nem indul el.",
            outcome_ok=False,
        )

    # 9. Módosított csomagok elutasítása.
    yield scene(
        stage="attacker",
        title="Módosított csomagok ellenőrzése",
        step=9,
        sub=0,
        sub_total=5,
        who="Támadó",
        what=(
            "módosított firmware-t, módosított manifestet, idegen kulccsal aláírt "
            "és régebbi verziójú csomagokat juttat az eszközhöz a valódi "
            "frissítési csatornán keresztül."
        ),
        where="",
        why=(
            "A cél annak igazolása, hogy az aláírás-, tartalom-, modell- "
            "és verzióellenőrzés mindegyiket elutasítja."
        ),
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
            outcome = "Az ellenőrző elutasította a módosított csomagot."
            log(f"[OK] {index}/5 — {scenario_title}: elutasítva.")
        elif actual == "accepted":
            outcome = "A módosított csomag átment az ellenőrzésen."
            log(f"[HIBA] {index}/5 — {scenario_title}: elfogadva.")
        else:
            outcome = "A kapott eredmény eltér a várt eredménytől."
            log(f"[FIGYELEM] {index}/5 — {scenario_title}: ellenőrizendő.")

        yield scene(
            stage="attacker",
            title=scenario_title,
            kicker=f"Támadási próba {index}/5",
            step=9,
            sub=index,
            sub_total=5,
            who="",
            what=build_attack_sentence(scenario),
            where="",
            why="",
            outcome=outcome,
            outcome_ok=passed,
        )

    # 10. Kulcsjelszó-ellenőrzés (csak a helyi kulcsra).
    yield scene(
        stage="bruteforce",
        title="Kulcsjelszó-ellenőrzés",
        step=10,
        who="Támadó",
        what=(
            "gyenge vagy újrahasznált jelszavakkal próbálja megnyitni a helyi "
            "kulcsfájlt. Éles környezetben a kulcs HSM-ben van, ahol ilyen "
            "támadás nem fér hozzá."
        ),
        where="helyi kulcsfájl",
        why=(
            "A jelszóval védett kulcs csak annyira biztonságos, amilyen erős "
            "a jelszó és amilyen szigorú a hozzáférés-korlátozás, ezért éles "
            "rendszerben HSM-et vagy kulcskezelő szolgáltatást használunk."
        ),
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
            step=10,
            who="Támadó",
            what="egy kipróbált jelölttel megnyitotta a helyi kulcsot.",
            where="helyi kulcs",
            why="A gyakori vagy újrahasznált jelszó gyengíti a kulcs védelmét.",
            outcome=f"Találat: {found_password}",
            outcome_ok=False,
        )
    else:
        yield scene(
            stage="bruteforce-failed",
            title="A kulcsjelszó-próba befejeződött",
            step=10,
            who="Támadó",
            what=f"{password_attack['attempts']} jelöltet próbált ki a helyi kulcsfájlon.",
            where="helyi kulcsfájl",
            why=(
                "Az eredmény csak a kipróbált jelöltekre érvényes; nem bizonyítja, "
                "hogy minden lehetséges jelszó sikertelen lenne."
            ),
            outcome="A kipróbált jelöltek között nem volt találat.",
            outcome_ok=True,
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
        password_summary = "A helyi kulcs jelszavát sikerült kitalálni."
    else:
        password_summary = (
            f"{password_attack['attempts']} helyi jelölt között nem volt találat."
        )

    log(
        f"[KÉSZ] Csomagellenőrzés és módosítási tesztek: "
        f"{firmware_pass_count}/{firmware_test_count}."
    )
    log(f"[KÉSZ] Jelszópróba: {password_summary}")

    yield scene(
        stage="done",
        title="A folyamat összesítése",
        step=11,
        who="",
        what=(
            f"{firmware_pass_count}/{firmware_test_count} csomagellenőrzési "
            f"teszt sikeres. {password_summary}"
        ),
        where="",
        why=(
            "Az aláírás, a manifest, a lenyomat, a verzióellenőrzés és a "
            "kulcsvédelem együtt alkotja a védelmi láncot."
        ),
        outcome=(
            "Minden vizsgálat rendben."
            if overall_ok
            else "Van kezelendő eredmény."
        ),
        outcome_ok=overall_ok,
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
    why: str = "",
    outcome: str = "",
    outcome_ok: bool = True,
) -> None:
    """Azonnal kirajzol egy jelenetet a folyamaton kívül (hiba, nullázás)."""

    story = scene(
        stage=stage,
        title=title,
        who=who,
        what=what,
        where=where,
        why=why,
        outcome=outcome,
        outcome_ok=outcome_ok,
    )

    st.session_state["story_state"] = story
    draw_story(story_placeholder, story)
    draw_stepper(stepper_placeholder, None)


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
    time.sleep(AUTO_ATTACK_DELAY_SECONDS)


def go_back() -> None:
    """Vissza a már látott jelenetre (gomb-callback)."""
    idx = st.session_state.get("scene_index", 0)
    st.session_state["scene_index"] = max(0, idx - 1)


def request_advance() -> None:
    """A Következő gomb jelzi, hogy a folyamat egy lépést haladjon."""
    st.session_state["advance"] = True

def show_finale() -> None:
    """Az utolsó lépés után a záróképernyő jelenik meg."""
    st.session_state["finale"] = True


def hide_finale() -> None:
    st.session_state["finale"] = False


def draw_finale() -> None:
    """Teljes oldalas záróképernyő; minden mást elfed."""

    def letters(text: str) -> str:
        return "".join(
            f'<span style="--i:{i}">'
            f'{"&nbsp;" if ch == " " else html.escape(ch)}</span>'
            for i, ch in enumerate(text)
        )

    words = "".join(
        f'<span style="--i:{i}">{html.escape(word)}</span>'
        for i, word in enumerate("Köszönöm a figyelmet!".split())
    )

    particles = "".join(
        f'<i style="--x:{(i * 37) % 100}%;--d:{6 + (i * 7) % 7}s;'
        f'--s:{(i * 3) % 5}s;--z:{3 + (i * 5) % 6}px"></i>'
        for i in range(28)
    )

    st.markdown(
        '<div class="finale">'
        '<div class="finale-grid"></div>'
        f'<div class="finale-particles">{particles}</div>'
        '<div class="finale-core">'
        '<div class="finale-badge">'
        '<span class="finale-ring"></span>'
        '<span class="finale-ring r2"></span>'
        f'{icon("shield", 54)}'
        "</div>"
        f'<div class="finale-title">{words}</div>'
        '<div class="finale-rule"></div>'
        '<div class="finale-by">Készítette</div>'
        f'<div class="finale-name">{letters("Kiss Szilárd Attila")}</div>'
        "</div>"
        "</div>",
        unsafe_allow_html=True,
    )
    st.button("← Vissza", key="finale_back", on_click=hide_finale)
    
    
# ---------------------------------------------------------------------
# Felület
# ---------------------------------------------------------------------

inject_css()

if st.session_state.get("finale"):
    draw_finale()

try:
    installed_version = read_installed_version(STATE)
except Exception:
    installed_version = 0

head_left, head_mid, head_right = st.columns([5, 3, 1.3], gap="medium")

head_left.markdown(
    '<div class="brand">'
    f'<div class="brand-icon">{icon("shield", 22)}</div>'
    "<div>"
    "<h1>Biztonságos firmware-frissítés</h1>"
    '<div class="brand-sub">Az aláírt csomag útja a gyártótól az eszközig, '
    "ellenőrzésekkel és öt támadási próbával.</div>"
    "</div>"
    "</div>",
    unsafe_allow_html=True,
)

head_mid.markdown(
    '<div class="meta">'
    f"<span>modell<b>{html.escape(DEVICE_MODEL)}</b></span>"
    f"<span>telepítve<b>v{installed_version}</b></span>"
    "</div>",
    unsafe_allow_html=True,
)

with head_right:
    if hasattr(st, "popover"):
        reset_box = st.popover("↺ Nullázás", use_container_width=True)
    else:
        reset_box = st.expander("↺ Nullázás", expanded=False)

    with reset_box:
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

st.markdown('<div style="height:.6rem"></div>', unsafe_allow_html=True)

started_before = bool(st.session_state.get("scenes"))

with st.form("update_form", clear_on_submit=False):
    file_col, password_col, action_col = st.columns(
        [1.6, 1.2, 0.55],
        gap="medium",
    )

    firmware_file = file_col.file_uploader(
        "Firmware-fájl",
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

    action_col.markdown('<div class="btn-spacer"></div>', unsafe_allow_html=True)
    run_demo = action_col.form_submit_button(
        "↻ Újraindítás" if started_before else "▶ Indítás",
        type="primary",
        use_container_width=True,
    )

st.markdown('<div style="height:.5rem"></div>', unsafe_allow_html=True)

stepper_col, story_col, terminal_col = st.columns(
    [0.95, 2.6, 1.2],
    gap="large",
)

with stepper_col:
    stepper_placeholder = st.empty()

with story_col:
    story_placeholder = st.empty()
    brute_guess_placeholder = st.empty()

with terminal_col:
    terminal_placeholder = st.empty()
    terminal = Terminal(terminal_placeholder)

default_story = scene(
    stage="idle",
    title="Készen állunk",
    who="",
    what="Válassz firmware-fájlt, és add meg a kulcs jelszavát.",
    where="",
    why="A program megmutatja az aláírást, az ellenőrzést és a támadási próbákat.",
)

draw_story(story_placeholder, st.session_state.get("story_state", default_story))
draw_stepper(stepper_placeholder, None)


# ---------------------------------------------------------------------
# Gombműveletek
# ---------------------------------------------------------------------

# A generátor több futáson át él, ezért a naplózó és a jelszópróba-megjelenítő
# függvényt mindig az aktuális futásból kell elérnie.
ctx = st.session_state.setdefault("ctx", {})
ctx["log"] = terminal.write
ctx["guess"] = show_guess


if run_demo:
    st.session_state["pipeline"] = None
    st.session_state.pop("scenes", None)
    st.session_state.pop("scene_index", None)
    terminal.clear()
    brute_guess_placeholder.empty()
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
        )
    else:
        try:
            firmware_bytes = firmware_file.getvalue()

            if len(firmware_bytes) > MAX_FIRMWARE_BYTES:
                raise ValueError("A firmware-fájl legfeljebb 64 MB lehet.")

            if not firmware_bytes:
                raise ValueError("A kiválasztott firmware-fájl üres.")

            meta = {"total": 22}
            st.session_state["meta"] = meta
            st.session_state["pipeline"] = run_pipeline(
                firmware_bytes,
                signing_password,
                firmware_file.name,
                lambda message: ctx["log"](message),
                lambda *args, **kwargs: ctx["guess"](*args, **kwargs),
                meta,
            )
            st.session_state["scenes"] = []
            st.session_state["scene_index"] = 0
            st.session_state["advance"] = True  # az 1. lépés megjelenítése

        except (OSError, ValueError) as exc:
            message = str(exc)
            terminal.write(f"[HIBA] {type(exc).__name__}: {message}")

            present(
                stage="error",
                title="A folyamat leállt",
                who="",
                what=message,
                where="",
                why="A program nem tudta folytatni a műveletet.",
                outcome=(
                    "Ellenőrizd a fájlt, a jelszót "
                    "és a mappajogosultságokat."
                ),
                outcome_ok=False,
            )

        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            terminal.write(f"[HIBA] Váratlan hiba: {message}")

            present(
                stage="error",
                title="Váratlan hiba történt",
                who="",
                what=message,
                where="",
                why="A folyamat nem tudott rendben befejeződni.",
                outcome="A részleteket a technikai napló tartalmazza.",
                outcome_ok=False,
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

        st.session_state["pipeline"] = None
        st.session_state.pop("scenes", None)
        st.session_state.pop("scene_index", None)

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
        )

    except OSError as exc:
        message = f"{type(exc).__name__}: {exc}"
        terminal.write(f"[HIBA] Nullázás: {message}")
        reset_feedback.error(
            f"Nem sikerült a nullázás: {type(exc).__name__}."
        )


# ---------------------------------------------------------------------
# Kézi léptetés
# ---------------------------------------------------------------------

if st.session_state.pop("advance", False):
    shown = st.session_state.setdefault("scenes", [])
    position = st.session_state.get("scene_index", 0)
    pipeline = st.session_state.get("pipeline")

    if shown and position < len(shown) - 1:
        # Már látott jelenet újranézése, a folyamat nem halad.
        st.session_state["scene_index"] = position + 1
    elif pipeline is not None:
        # Itt fut le a következő lépés kódja (a jelszópróbánál élő animációval).
        try:
            shown.append(next(pipeline))
            st.session_state["scene_index"] = len(shown) - 1
        except StopIteration:
            st.session_state["pipeline"] = None
        except Exception as exc:
            message = str(exc) or type(exc).__name__
            terminal.write(f"[HIBA] {type(exc).__name__}: {message}")
            shown.append(
                scene(
                    stage="error",
                    title="A folyamat leállt",
                    step=shown[-1]["step"] if shown else 0,
                    who="",
                    what=message,
                    where="",
                    why="A program nem tudta folytatni a műveletet.",
                    outcome="Nullázd a demót, vagy add meg a helyes jelszót, majd indítsd újra.",
                    outcome_ok=False,
                )
            )
            st.session_state["scene_index"] = len(shown) - 1
            st.session_state["pipeline"] = None

        brute_guess_placeholder.empty()


if st.session_state.get("scenes"):
    scenes = st.session_state["scenes"]
    idx = max(0, min(st.session_state.get("scene_index", 0), len(scenes) - 1))
    st.session_state["scene_index"] = idx
    current = scenes[idx]

    draw_story(story_placeholder, current, fx=idx)
    draw_stepper(stepper_placeholder, current)

    total = max(
        len(scenes),
        int(st.session_state.get("meta", {}).get("total", len(scenes))),
    )

    on_done = idx == len(scenes) - 1 and current["stage"] == "done"
    at_end = (
        idx == len(scenes) - 1
        and not on_done
        and st.session_state.get("pipeline") is None
    )
    with story_col:
        st.markdown('<div class="nav-rule"></div>', unsafe_allow_html=True)

        prev_col, counter_col, next_col = st.columns([1, 1, 1.15])

        prev_col.button(
            "← Előző",
            disabled=idx == 0,
            key="scene_prev",
            on_click=go_back,
            use_container_width=True,
        )
        counter_col.markdown(
            f'<div class="counter">{idx + 1} / {total}</div>',
            unsafe_allow_html=True,
        )
        next_col.button(
            "Befejezés →" if on_done else "Következő lépés →",
            disabled=at_end,
            key="scene_next",
            type="primary",
            on_click=show_finale if on_done else request_advance,
            use_container_width=True,
        )