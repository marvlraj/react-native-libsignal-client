package expo.modules.libsignalclient

import expo.modules.kotlin.modules.ModuleDefinitionBuilder

internal fun ModuleDefinitionBuilder.registerSessionAndRatchetFunctions(module: ReactNativeLibsignalClientModule) {
    Function("sessionRecordArchiveCurrentState", module::sessionRecordArchiveCurrentState)
    Function("sessionRecordGetLocalRegistrationId", module::sessionRecordGetLocalRegistrationId)
    Function("sessionRecordGetRemoteRegistrationId", module::sessionRecordGetRemoteRegistrationId)
    Function("sessionRecordHasUsableSenderChain", module::sessionRecordHasUsableSenderChain)
    Function("sessionRecordCurrentRatchetKeyMatches", module::sessionRecordCurrentRatchetKeyMatches)

    Function("sessionCipherEncryptMessage", module::sessionCipherEncryptMessage)
    Function("sessionCipherDecryptSignalMessage", module::sessionCipherDecryptSignalMessage)
    Function("sessionCipherDecryptPreKeySignalMessage", module::sessionCipherDecryptPreKeySignalMessage)

    Function("signalMessageGetBody", module::signalMessageGetBody)
    Function("signalMessageGetCounter", module::signalMessageGetCounter)
    Function("signalMessageGetMessageVersion", module::signalMessageGetMessageVersion)
    Function("signalMessageVerifyMac", module::signalMessageVerifyMac)

    Function("preKeySignalMessageGetPreKeyId", module::preKeySignalMessageGetPreKeyId)
    Function("preKeySignalMessageGetRegistrationId", module::preKeySignalMessageGetRegistrationId)
    Function("preKeySignalMessageGetSignedPreKeyId", module::preKeySignalMessageGetSignedPreKeyId)
    Function("preKeySignalMessageGetVersion", module::preKeySignalMessageGetVersion)

    Function("plaintextContentFromDecryptionErrorMessage", module::plaintextContentFromDecryptionErrorMessage)
    Function("plaintextContentGetBody", module::plaintextContentGetBody)
    Function("decryptionErrorMessageForOriginalMessage", module::decryptionErrorMessageForOriginalMessage)
    Function("decryptionErrorMessageExtractFromSerializedContent", module::decryptionErrorMessageExtractFromSerializedContent)
    Function("decryptionErrorMessageGetTimestamp", module::decryptionErrorMessageGetTimestamp)
    Function("decryptionErrorMessageGetDeviceId", module::decryptionErrorMessageGetDeviceId)
    Function("decryptionErrorMessageGetRatchetKey", module::decryptionErrorMessageGetRatchetKey)
}
