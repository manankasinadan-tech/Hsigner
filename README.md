# HSIGNER (`com.hephaistos.hsigner`)

Module satellite Android **100 % headless** (sans interface graphique propre) pour l'écosystème **HEPHAISTOS**, dédié à la vérification cryptographique avancée des signatures APK (**V1 JAR, V2, V3, V3.1 Key Rotation et V4 `.idsig`**).

## Fonctionnalités
- **Découverte & UI déclarative HEPHAISTOS** (`res/raw/hephaistos_manifest.json`) :
  - Sélecteur multi-APK (`file_picker`) via le gestionnaire de fichiers de HEPHAISTOS.
  - Bouton **Verify** lançant l'analyse cryptographique V1–V4 et diffusant le rapport détaillé dans le terminal HEPHAISTOS (`LOG` + `PROGRESS` + `COMMAND_RESULT`).
  - Bouton **Readme** affichant la documentation inter-modulaire et générant le document téléchargeable `HSIGNER_README.md`.
- **Interopérabilité totale** : commandable par HEPHAISTOS (`com.hephaistos.launcher`), tout terminal ou toute autre application via `ModuleEngineService` (`com.hephaistos.action.EXECUTE`), `ModuleBroadcastCommandReceiver` ou `HsignerContentProvider` (`content://com.hephaistos.hsigner.provider`).

## Compilation sur GitHub Actions
1. Poussez ce dépôt sur GitHub (`main` ou `master`).
2. Ouvrez l'onglet **Actions** -> **Build HSIGNER APK**.
3. Téléchargez l'artefact **`HSIGNER-debug-apk`** et installez-le sur votre téléphone Android avec HEPHAISTOS.
