# Warehouse Cabinet GUI — Viola János — MYBP86

## Hallgató
- **Név:** Viola János
- **Neptun:** **MYBP86**

> **Megjegyzés:** Ez a beadandó egy **régebbi céges projekt** Python-alapú, oktatási célra általánosított változata. **Nem tartalmaz bizalmas információt**, így benyújtható. A program reményeim szerint megfelel az elvárásoknak a függvényekben és az osztályban nem szerepel a **VJ** monogram csak a neptun kód**MYBP86**.
A céges program C#-ban WPF GUI interfacel készült postgresql-el.
---

## Feladat leírása
Asztali alkalmazás raktári **szekrények** és azok **6 polcának** vizualizálására és kezelésére (függőleges nézet: **A6 felül → A1 alul**).

**Fő funkciók**
- Szekrények létrehozása (A, B, C, …).
- Tételek hozzáadása polcokra megadott **típussal** (BOX, SWITCH, PDU, OTHER).
- **Automatikus azonosító-generálás**: `TES-<CABINET><SHELF>-<TYPE><INDEX>` (pl. `TES-A1-BOX1`).
- Adattárolás: **SQLite**.
- GUI: **tkinter**, eseménykezeléssel.
- Kódstílus: **PEP8/flake8**, típusannotációk, bemeneti validáció.


---

## Gyors indítás
```bash
python app_MYBP86.py
