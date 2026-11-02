package expo.modules.libsignalclient

import expo.modules.kotlin.modules.ModuleDefinitionBuilder

internal fun ModuleDefinitionBuilder.registerZkGroupFunctions(module: ReactNativeLibsignalClientModule) {
    Function("groupPublicParamsGetGroupIdentifier", module::groupPublicParamsGetGroupIdentifier)
    Function("groupSecretParamsGenerateDeterministic", module::groupSecretParamsGenerateDeterministic)
    Function("groupSecretParamsDeriveFromMasterKey", module::groupSecretParamsDeriveFromMasterKey)
    Function("groupSecretParamsGetPublicParams", module::groupSecretParamsGetPublicParams)
    Function("groupSecretParamsGetMasterKey", module::groupSecretParamsGetMasterKey)
    Function("groupSecretParamsDecryptBlobWithPadding", module::groupSecretParamsDecryptBlobWithPadding)
    Function("groupSecretParamsEncryptBlobWithPaddingDeterministic", module::groupSecretParamsEncryptBlobWithPaddingDeterministic)
    Function("groupSecretParamsDecryptProfileKey", module::groupSecretParamsDecryptProfileKey)
    Function("groupSecretParamsEncryptProfileKey", module::groupSecretParamsEncryptProfileKey)
    Function("groupSecretParamsDecryptServiceId", module::groupSecretParamsDecryptServiceId)
    Function("groupSecretParamsEncryptServiceId", module::groupSecretParamsEncryptServiceId)
    Function("groupSecretParamsEncryptCiphertext", module::groupSecretParamsEncryptCiphertext)

    Function("serverPublicParamsVerifySignature", module::serverPublicParamsVerifySignature)
    Function("serverPublicParamsCreateAuthCredentialWithPniPresentationDeterministic", module::serverPublicParamsCreateAuthCredentialWithPniPresentationDeterministic)
    Function("serverPublicParamsReceiveAuthCredentialWithPniAsServiceId", module::serverPublicParamsReceiveAuthCredentialWithPniAsServiceId)
    Function("serverPublicParamsCreateExpiringProfileKeyCredentialPresentationDeterministic", module::serverPublicParamsCreateExpiringProfileKeyCredentialPresentationDeterministic)
    Function("serverPublicParamsReceiveExpiringProfileKeyCredential", module::serverPublicParamsReceiveExpiringProfileKeyCredential)
    Function("serverPublicParamsCreateProfileKeyCredentialRequestContextDeterministic", module::serverPublicParamsCreateProfileKeyCredentialRequestContextDeterministic)
    Function("serverSecretParamsGenerateDeterministic", module::serverSecretParamsGenerateDeterministic)
    Function("serverSecretParamsGetPublicParams", module::serverSecretParamsGetPublicParams)
    Function("serverSecretParamsSignDeterministic", module::serverSecretParamsSignDeterministic)
    Function("serverSecretParamsIssueAuthCredentialWithPniAsServiceIdDeterministic", module::serverSecretParamsIssueAuthCredentialWithPniAsServiceIdDeterministic)
    Function("serverSecretParamsIssueAuthCredentialWithPniZkcDeterministic", module::serverSecretParamsIssueAuthCredentialWithPniZkcDeterministic)
    Function("serverSecretParamsVerifyAuthCredentialPresentation", module::serverSecretParamsVerifyAuthCredentialPresentation)
    Function("serverSecretParamsIssueExpiringProfileKeyCredentialDeterministic", module::serverSecretParamsIssueExpiringProfileKeyCredentialDeterministic)
    Function("serverSecretParamsVerifyProfileKeyCredentialPresentation", module::serverSecretParamsVerifyProfileKeyCredentialPresentation)
    Function("genericServerSecretParamsGenerateDeterministic", module::genericServerSecretParamsGenerateDeterministic)
    Function("genericServerSecretParamsGetPublicParams", module::genericServerSecretParamsGetPublicParams)

    Function("authCredentialPresentationGetRedemptionTime", module::authCredentialPresentationGetRedemptionTime)
    Function("authCredentialPresentationGetPniCiphertext", module::authCredentialPresentationGetPniCiphertext)
    Function("authCredentialPresentationGetUuidCiphertext", module::authCredentialPresentationGetUuidCiphertext)
    Function("profileKeyCredentialRequestContextGetRequest", module::profileKeyCredentialRequestContextGetRequest)
    Function("profileKeyCredentialPresentationGetProfileKeyCiphertext", module::profileKeyCredentialPresentationGetProfileKeyCiphertext)
    Function("profileKeyCredentialPresentationGetUuidCiphertext", module::profileKeyCredentialPresentationGetUuidCiphertext)
    Function("expiringProfileKeyCredentialGetExpirationTime", module::expiringProfileKeyCredentialGetExpirationTime)
}
