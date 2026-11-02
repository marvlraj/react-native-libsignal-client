package expo.modules.libsignalclient

import expo.modules.kotlin.modules.ModuleDefinitionBuilder

internal fun ModuleDefinitionBuilder.registerCryptoPrimitivesFunctions(module: ReactNativeLibsignalClientModule) {
    Function("hkdfDeriveSecrets", module::hkdfDeriveSecrets)
    Function("HmacSHA256", module::HmacSHA256)
    Function("ConstantTimeEqual", module::ConstantTimeEqual)
    Function("generateRandomBytes", module::generateRandomBytes)

    Function("Aes256GcmEncrypt", module::Aes256GcmEncrypt)
    Function("Aes256GcmDecrypt", module::Aes256GcmDecrypt)
    Function("Aes256CbcEncrypt", module::Aes256CbcEncrypt)
    Function("Aes256CbcDecrypt", module::Aes256CbcDecrypt)
    Function("Aes256CtrEncrypt", module::Aes256CtrEncrypt)
    Function("Aes256CtrDecrypt", module::Aes256CtrDecrypt)

    Function("profileKeyGetCommitment", module::profileKeyGetCommitment)
    Function("profileKeyGetVersion", module::profileKeyGetVersion)
    Function("profileKeyDeriveAccessKey", module::profileKeyDeriveAccessKey)
}
