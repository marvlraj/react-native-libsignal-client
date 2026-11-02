package expo.modules.libsignalclient

import expo.modules.kotlin.modules.ModuleDefinitionBuilder

internal fun ModuleDefinitionBuilder.registerBackupFunctions(module: ReactNativeLibsignalClientModule) {
    Function("backupAuthCredentialRequestContextNew", module::backupAuthCredentialRequestContextNew)
    Function("backupAuthCredentialRequestContextGetRequest", module::backupAuthCredentialRequestContextGetRequest)
    Function("backupAuthCredentialRequestContextReceiveResponse", module::backupAuthCredentialRequestContextReceiveResponse)
    Function("backupAuthCredentialRequestIssueDeterministic", module::backupAuthCredentialRequestIssueDeterministic)
    Function("backupAuthCredentialPresentationVerify", module::backupAuthCredentialPresentationVerify)
    Function("backupAuthCredentialPresentationGetBackupId", module::backupAuthCredentialPresentationGetBackupId)
    Function("backupAuthCredentialPresentationGetBackupLevel", module::backupAuthCredentialPresentationGetBackupLevel)
    Function("backupAuthCredentialPresentationGetType", module::backupAuthCredentialPresentationGetType)
    Function("backupAuthCredentialPresentDeterministic", module::backupAuthCredentialPresentDeterministic)
    Function("backupAuthCredentialGetBackupId", module::backupAuthCredentialGetBackupId)
    Function("backupAuthCredentialGetBackupLevel", module::backupAuthCredentialGetBackupLevel)
    Function("backupAuthCredentialGetType", module::backupAuthCredentialGetType)

    Function("backupKeyDeriveBackupId", module::backupKeyDeriveBackupId)
    Function("backupKeyDeriveEcKey", module::backupKeyDeriveEcKey)
    Function("backupKeyDeriveLocalBackupMetadataKey", module::backupKeyDeriveLocalBackupMetadataKey)
    Function("backupKeyDeriveMediaId", module::backupKeyDeriveMediaId)
    Function("backupKeyDeriveMediaEncryptionKey", module::backupKeyDeriveMediaEncryptionKey)
    Function("backupKeyDeriveThumbnailTransitEncryptionKey", module::backupKeyDeriveThumbnailTransitEncryptionKey)

    Function("accountEntropyPoolGenerate", module::accountEntropyPoolGenerate)
    Function("accountEntropyPoolIsValid", module::accountEntropyPoolIsValid)
    Function("accountEntropyPoolDeriveSvrKey", module::accountEntropyPoolDeriveSvrKey)
    Function("accountEntropyPoolDeriveBackupKey", module::accountEntropyPoolDeriveBackupKey)

    Function("messageBackupKeyFromAccountEntropyPool", module::messageBackupKeyFromAccountEntropyPool)
    Function("messageBackupKeyFromBackupKeyAndBackupId", module::messageBackupKeyFromBackupKeyAndBackupId)
    Function("messageBackupKeyGetHmacKey", module::messageBackupKeyGetHmacKey)
    Function("messageBackupKeyGetAesKey", module::messageBackupKeyGetAesKey)

    Function("messageBackupValidatorValidate", module::messageBackupValidatorValidate)
    Function("onlineBackupValidatorNew", module::onlineBackupValidatorNew)
    Function("onlineBackupValidatorAddFrame", module::onlineBackupValidatorAddFrame)
    Function("onlineBackupValidatorFinalize", module::onlineBackupValidatorFinalize)
    Function("comparableBackupReadUnencrypted", module::comparableBackupReadUnencrypted)
    Function("comparableBackupGetInfo", module::comparableBackupGetInfo)
}
