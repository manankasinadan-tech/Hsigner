# HSIGNER (`com.hephaistos.hsigner`)

Module satellite Android **100 % headless** (sans interface graphique propre) pour l'écosystème **HEPHAISTOS**, dédié à la vérification cryptographique avancée des signatures APK (**V1 JAR, V2, V3, V3.1 Key Rotation et V4 `.idsig`**).

## Fonctionnalités
- **Tableau de bord déclaratif HEPHAISTOS** (`res/raw/hephaistos_manifest.json`) :
  - Sélecteur multi-APK (`file_picker`) et sélecteur optionnel de fichier compagnon V4 `.idsig`.
  - Sélecteur de niveau de détail (`ultra_complet`, `standard`, `compact`) et bascules d'options (bits hex/Base64 bruts, empreintes du fichier APK, audit manifeste & permissions).
  - Bouton **Verify** lançant l'audit cryptographique & forensique complet (V1–V4, SourceStamp, X.509 avancé, SPKI, empreintes Play/Firebase, manifeste & score de confiance) et diffusant le rapport dans le terminal HEPHAISTOS (`LOG` + `PROGRESS` + `COMMAND_RESULT`).
  - Boutons **Autoriser l'accès stockage**, **Diagnostic Moteur** et **Readme** (`HSIGNER_README.md` téléchargeable).
- **Interopérabilité totale** : commandable par HEPHAISTOS (`com.hephaistos.launcher`), tout terminal ou toute autre application via `ModuleEngineService` (`com.hephaistos.action.EXECUTE`), `ModuleBroadcastCommandReceiver` ou `HsignerContentProvider` (`content://com.hephaistos.hsigner.provider`).

## Compilation sur GitHub Actions
1. Poussez ce dépôt sur GitHub (`main` ou `master`).
2. Ouvrez l'onglet **Actions** -> **Build HSIGNER APK**.
3. Téléchargez l'artefact **`HSIGNER-debug-apk`** et installez-le sur votre téléphone Android avec HEPHAISTOS.
