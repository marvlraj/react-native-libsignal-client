package expo.modules.libsignalclient

import expo.modules.kotlin.modules.ModuleDefinitionBuilder

internal fun ModuleDefinitionBuilder.registerGroupAndSenderKeyFunctions(module: ReactNativeLibsignalClientModule) {
    Function("senderKeyMessageGetCipherText", module::senderKeyMessageGetCipherText)
    Function("senderKeyMessageGetIteration", module::senderKeyMessageGetIteration)
    Function("senderKeyMessageGetChainId", module::senderKeyMessageGetChainId)
    Function("senderKeyMessageGetDistributionId", module::senderKeyMessageGetDistributionId)
    Function("senderKeyMessageVerifySignature", module::senderKeyMessageVerifySignature)

    Function("senderKeyDistributionMessageGetChainKey", module::senderKeyDistributionMessageGetChainKey)
    Function("senderKeyDistributionMessageGetIteration", module::senderKeyDistributionMessageGetIteration)
    Function("senderKeyDistributionMessageGetChainId", module::senderKeyDistributionMessageGetChainId)
    Function("senderKeyDistributionMessageGetDistributionId", module::senderKeyDistributionMessageGetDistributionId)
    Function("senderKeyDistributionMessageProcess", module::senderKeyDistributionMessageProcess)
    Function("senderKeyDistributionMessageCreate", module::senderKeyDistributionMessageCreate)

    Function("groupCipherEncryptMessage", module::groupCipherEncryptMessage)
    Function("groupCipherDecryptMessage", module::groupCipherDecryptMessage)

    Function("unidentifiedSenderMessageContentNew", module::unidentifiedSenderMessageContentNew)
    Function("unidentifiedSenderMessageContentGetContents", module::unidentifiedSenderMessageContentGetContents)
    Function("unidentifiedSenderMessageContentGetMsgType", module::unidentifiedSenderMessageContentGetMsgType)
    Function("unidentifiedSenderMessageContentGetSenderCert", module::unidentifiedSenderMessageContentGetSenderCert)
    Function("unidentifiedSenderMessageContentGetContentHint", module::unidentifiedSenderMessageContentGetContentHint)
    Function("unidentifiedSenderMessageContentGetGroupId", module::unidentifiedSenderMessageContentGetGroupId)
    Function("sealedSenderDecryptToUsmc", module::sealedSenderDecryptToUsmc)
    Function("sealedSenderMultiRecipientEncrypt", module::sealedSenderMultiRecipientEncrypt)
    Function("sealedSenderMultiRecipientMessageForSingleRecipient", module::sealedSenderMultiRecipientMessageForSingleRecipient)
    Function("sealedSenderEncrypt", module::sealedSenderEncrypt)

    Function("groupSendFullTokenGetExpiration", module::groupSendFullTokenGetExpiration)
    Function("groupSendFullTokenVerify", module::groupSendFullTokenVerify)
    Function("groupSendTokenToFullToken", module::groupSendTokenToFullToken)
    Function("groupSendDerivedKeyPairForExpiration", module::groupSendDerivedKeyPairForExpiration)
    Function("groupSendEndorsementCombine", module::groupSendEndorsementCombine)
    Function("groupSendEndorsementRemove", module::groupSendEndorsementRemove)
    Function("groupSendEndorsementToToken", module::groupSendEndorsementToToken)
    Function("groupSendEndorsementsResponseIssueDeterministic", module::groupSendEndorsementsResponseIssueDeterministic)
    Function("groupSendEndorsementsResponseGetExpiration", module::groupSendEndorsementsResponseGetExpiration)
    Function("groupSendEndorsementsResponseReceiveAndCombineWithServiceIds", module::groupSendEndorsementsResponseReceiveAndCombineWithServiceIds)
    Function("groupSendEndorsementsResponseReceiveAndCombineWithCiphertexts", module::groupSendEndorsementsResponseReceiveAndCombineWithCiphertexts)
}
