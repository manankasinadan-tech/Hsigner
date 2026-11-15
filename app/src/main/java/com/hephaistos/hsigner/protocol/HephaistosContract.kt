package com.hephaistos.hsigner.protocol

/**
 * Constantes officielles du protocole inter-modulaire HEPHAISTOS et des commandes HSIGNER.
 */
object HephaistosContract {
    const val LAUNCHER_PACKAGE = "com.hephaistos.launcher"
    const val MODULE_PACKAGE = "com.hephaistos.hsigner"

    // Actions officielles HEPHAISTOS
    const val ACTION_MODULE = "com.hephaistos.action.MODULE"
    const val ACTION_EXECUTE = "com.hephaistos.action.EXECUTE"
    const val ACTION_LOG = "com.hephaistos.action.LOG"
    const val ACTION_PROGRESS = "com.hephaistos.action.PROGRESS"
    const val ACTION_SHOW_POPUP = "com.hephaistos.action.SHOW_POPUP"
    const val ACTION_COMMAND_RESULT = "com.hephaistos.action.COMMAND_RESULT"
    const val ACTION_CANCEL_TASK = "com.hephaistos.action.CANCEL_TASK"

    // Action broadcast optionnelle pour terminaux / scripts externes
    const val ACTION_EXECUTE_BROADCAST = "com.hephaistos.hsigner.action.EXECUTE_BROADCAST"

    // Métadonnées du manifeste
    const val META_DATA_MANIFEST = "com.hephaistos.module.manifest"

    // Extras officielles HEPHAISTOS
    const val EXTRA_COMMAND_ID = "hephaistos.extra.COMMAND_ID"
    const val EXTRA_PARAMS_JSON = "hephaistos.extra.PARAMS_JSON"
    const val EXTRA_SOURCE_PACKAGE = "hephaistos.extra.SOURCE_PACKAGE"
    const val EXTRA_TASK_ID = "hephaistos.extra.TASK_ID"
    const val EXTRA_LEVEL = "hephaistos.extra.LEVEL"
    const val EXTRA_MESSAGE = "hephaistos.extra.MESSAGE"
    const val EXTRA_TITLE = "hephaistos.extra.TITLE"
    const val EXTRA_PROGRESS = "hephaistos.extra.PROGRESS"
    const val EXTRA_COMPLETED = "hephaistos.extra.COMPLETED"
    const val EXTRA_ERROR = "hephaistos.extra.ERROR"
    const val EXTRA_CAN_CANCEL = "hephaistos.extra.CAN_CANCEL"
    const val EXTRA_RESULT_JSON = "hephaistos.extra.RESULT_JSON"

    // Extras pour SHOW_POPUP
    const val EXTRA_POPUP_ID = "hephaistos.extra.POPUP_ID"
    const val EXTRA_CONFIRM_LABEL = "hephaistos.extra.CONFIRM_LABEL"
    const val EXTRA_CANCEL_LABEL = "hephaistos.extra.CANCEL_LABEL"
    const val EXTRA_DOWNLOAD_URI = "hephaistos.extra.DOWNLOAD_URI"

    // Niveaux de log terminal
    const val LOG_INFO = "INFO"
    const val LOG_OUT = "OUT"
    const val LOG_ERR = "ERR"

    // Commandes exposées dans res/raw/hephaistos_manifest.json
    const val CMD_VERIFY_APK = "verify_apk"
    const val CMD_GET_README = "get_readme"
    const val CMD_EXPORT_README_FILE = "export_readme_file"
    const val CMD_INSPECT_CAPABILITIES = "inspect_capabilities"

    // Autorités Provider
    const val FILE_PROVIDER_AUTHORITY = "com.hephaistos.hsigner.fileprovider"
    const val CONTENT_PROVIDER_AUTHORITY = "com.hephaistos.hsigner.provider"
}
