package expo.modules.libsignalclient

import android.util.Base64
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.types.toJSValue
import org.signal.libsignal.messagebackup.AccountEntropyPool
import org.signal.libsignal.messagebackup.BackupKey
import org.signal.libsignal.messagebackup.ComparableBackup
import org.signal.libsignal.messagebackup.MessageBackup
import org.signal.libsignal.messagebackup.MessageBackup.Purpose
import org.signal.libsignal.messagebackup.MessageBackupKey
import org.signal.libsignal.messagebackup.OnlineBackupValidator
import org.signal.libsignal.metadata.SealedSessionCipher
import org.signal.libsignal.metadata.certificate.CertificateValidator
import org.signal.libsignal.metadata.certificate.InvalidCertificateException
import org.signal.libsignal.metadata.certificate.SenderCertificate
import org.signal.libsignal.metadata.certificate.ServerCertificate
import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessageContent
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.InvalidKeyException
import org.signal.libsignal.protocol.InvalidMessageException
import org.signal.libsignal.protocol.ServiceId
import org.signal.libsignal.protocol.ServiceId.Aci
import org.signal.libsignal.protocol.ServiceId.Pni
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.Curve
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPrivateKey
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.groups.GroupCipher
import org.signal.libsignal.protocol.groups.GroupSessionBuilder
import org.signal.libsignal.protocol.groups.state.InMemorySenderKeyStore
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord
import org.signal.libsignal.protocol.kdf.HKDF
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.DecryptionErrorMessage
import org.signal.libsignal.protocol.message.PlaintextContent
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SenderKeyDistributionMessage
import org.signal.libsignal.protocol.message.SenderKeyMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore
import org.signal.libsignal.protocol.util.KeyHelper
import org.signal.libsignal.zkgroup.GenericServerPublicParams
import org.signal.libsignal.zkgroup.GenericServerSecretParams
import org.signal.libsignal.zkgroup.NotarySignature
import org.signal.libsignal.zkgroup.ServerPublicParams
import org.signal.libsignal.zkgroup.ServerSecretParams
import org.signal.libsignal.zkgroup.VerificationFailedException
import org.signal.libsignal.zkgroup.auth.AuthCredentialPresentation
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPni
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPniResponse
import org.signal.libsignal.zkgroup.auth.ClientZkAuthOperations
import org.signal.libsignal.zkgroup.auth.ServerZkAuthOperations
import org.signal.libsignal.zkgroup.backups.BackupAuthCredential
import org.signal.libsignal.zkgroup.backups.BackupAuthCredentialPresentation
import org.signal.libsignal.zkgroup.backups.BackupAuthCredentialRequest
import org.signal.libsignal.zkgroup.backups.BackupAuthCredentialRequestContext
import org.signal.libsignal.zkgroup.backups.BackupAuthCredentialResponse
import org.signal.libsignal.zkgroup.backups.BackupCredentialType
import org.signal.libsignal.zkgroup.backups.BackupLevel
import org.signal.libsignal.zkgroup.groups.ClientZkGroupCipher
import org.signal.libsignal.zkgroup.groups.GroupMasterKey
import org.signal.libsignal.zkgroup.groups.GroupPublicParams
import org.signal.libsignal.zkgroup.groups.GroupSecretParams
import org.signal.libsignal.zkgroup.groups.ProfileKeyCiphertext
import org.signal.libsignal.zkgroup.groups.UuidCiphertext
import org.signal.libsignal.zkgroup.groupsend.GroupSendDerivedKeyPair
import org.signal.libsignal.zkgroup.groupsend.GroupSendEndorsement
import org.signal.libsignal.zkgroup.groupsend.GroupSendEndorsementsResponse
import org.signal.libsignal.zkgroup.groupsend.GroupSendFullToken
import org.signal.libsignal.zkgroup.profiles.ClientZkProfileOperations
import org.signal.libsignal.zkgroup.profiles.ExpiringProfileKeyCredential
import org.signal.libsignal.zkgroup.profiles.ExpiringProfileKeyCredentialResponse
import org.signal.libsignal.zkgroup.profiles.ProfileKey
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCommitment
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialPresentation
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialRequest
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialRequestContext
import org.signal.libsignal.zkgroup.profiles.ServerZkProfileOperations
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.security.SecureRandom
import java.time.Instant
import java.util.Optional
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

typealias StringifiedProtocolAddress = String
typealias SerializedAddressedKeys = Map<StringifiedProtocolAddress, String>
typealias RegistrationId = Int
typealias IdKey = String
typealias Keypair = String
typealias OwnerData = Pair<Keypair, RegistrationId>
typealias IdentityStoreData = Pair<IdKey, OwnerData>

fun getDeviceIdAndServiceId(address: String): Pair<String, Int> {
  val (serviceId, deviceId) = address.split(".")
  return Pair(serviceId, deviceId.toInt())
}
fun updateSessionStoreStateFromInMemoryProtocolStore(store: InMemorySignalProtocolStoreWithPrekeysList, address: SignalProtocolAddress ): SerializedAddressedKeys {
  val sessionRecords = store.loadExistingSessions(listOf(address))
  val updatedStore = mutableMapOf<String, String>()
  for (sessionRecord in sessionRecords) {
    updatedStore[address.toString()] =  Base64.encodeToString(sessionRecord.serialize(), Base64.NO_WRAP)
  }
  return updatedStore
}
fun updateIdentityStoreStateFromInMemoryProtocolStore(store: InMemorySignalProtocolStoreWithPrekeysList, address: SignalProtocolAddress): SerializedAddressedKeys {
    val identityKey = store.getIdentity(address)
    val updatedStore = mutableMapOf<String, String>()
    updatedStore[address.toString()] =  Base64.encodeToString(identityKey.serialize(), Base64.NO_WRAP)
    return updatedStore
}
fun updatePreKeyStoreStateFromInMemoryProtocolStore(store: InMemorySignalProtocolStoreWithPrekeysList) : SerializedAddressedKeys {
    val updatedStore = mutableMapOf<String, String>()
    val preKeys = store.loadPreKeys()
    for (entry in preKeys) {
        updatedStore[entry.id.toString()] = Base64.encodeToString(entry.serialize(), Base64.NO_WRAP)
    }
    return updatedStore
}
fun updateSignedPreKeyStoreStateFromInMemoryProtocolStore(store: InMemorySignalProtocolStoreWithPrekeysList): SerializedAddressedKeys {
    val updatedStore = mutableMapOf<String, String>()
    val signedPreKeys = store.loadSignedPreKeys()
    for (entry in signedPreKeys) {
        updatedStore[entry.id.toString()] = Base64.encodeToString(entry.serialize(), Base64.NO_WRAP)
    }
    return updatedStore
}
fun updateKyberPreKeyStoreStateFromInMemoryProtocolStore(store: InMemorySignalProtocolStoreWithPrekeysList): SerializedAddressedKeys {
    val updatedStore = mutableMapOf<String, String>()
    val kyberPreKeys = store.loadKyberPreKeys()
    for (entry in kyberPreKeys) {
        updatedStore[entry.id.toString()] = Base64.encodeToString(entry.serialize(), Base64.NO_WRAP)
    }
    return updatedStore
}

class ReactNativeLibsignalClientModule : Module() {
  private val handles = mutableMapOf<String, Any>()
  internal val logListener: (ReactNativeLibsignalClientLogType) -> String = fun (l: ReactNativeLibsignalClientLogType): String {
      val m = HashMap<String, String>()
      m["msg"] = l.messages.contentToString()
      m["level"] = l.level

      this@ReactNativeLibsignalClientModule.sendEvent("onLogGenerated", m)

      return "null"
  }

  override fun definition() = ModuleDefinition {
    Name("ReactNativeLibsignalClient")
    OnCreate {
      ReactNativeLibsignalClientLogger.addCallback(logListener)
      ReactNativeLibsignalClientLogger.initiate()
    }
    Events("onLogGenerated")

    registerIdentityAndKeyFunctions(this@ReactNativeLibsignalClientModule)
    registerSessionAndRatchetFunctions(this@ReactNativeLibsignalClientModule)
    registerGroupAndSenderKeyFunctions(this@ReactNativeLibsignalClientModule)
    registerCryptoPrimitivesFunctions(this@ReactNativeLibsignalClientModule)
    registerZkGroupFunctions(this@ReactNativeLibsignalClientModule)
    registerBackupFunctions(this@ReactNativeLibsignalClientModule)
  }

    internal fun serviceIdServiceIdBinary(fixedWidthServiceId: ByteArray) : ByteArray {
        return ServiceId.parseFromFixedWidthBinary(fixedWidthServiceId).toServiceIdBinary()
    }
    internal fun serviceIdServiceIdString(fixedWidthServiceId: ByteArray) : String {
        return ServiceId.parseFromFixedWidthBinary(fixedWidthServiceId).toServiceIdString()
    }
    internal fun serviceIdServiceIdLog(fixedWidthServiceId: ByteArray) : String {
        return ServiceId.parseFromFixedWidthBinary(fixedWidthServiceId).toLogString()
    }
    internal fun serviceIdParseFromServiceIdBinary(serviceIdBinary: ByteArray) : ByteArray {
        return ServiceId.parseFromBinary(serviceIdBinary).toServiceIdFixedWidthBinary()
    }
    internal fun serviceIdParseFromServiceIdString(serviceIdString: String) : ByteArray {
        return ServiceId.parseFromString(serviceIdString).toServiceIdFixedWidthBinary()
    }


  internal fun privateKeyGenerate() : ByteArray {
    val keypair = Curve.generateKeyPair()
    return keypair.privateKey.serialize()
  }
  internal fun privateKeyAgree(serializedPrivateKey: ByteArray, serializedOtherPublicKey : ByteArray) : ByteArray {
    val privateKey = Curve.decodePrivatePoint(serializedPrivateKey)
    val publicKey = ECPublicKey(serializedOtherPublicKey)
    return privateKey.calculateAgreement(publicKey)
  }
  internal fun privateKeyGetPublicKey(serializedPrivateKey: ByteArray) : ByteArray {
    val privateKey = Curve.decodePrivatePoint(serializedPrivateKey)
    return privateKey.publicKey().serialize()
  }
  internal fun publicKeyCompare(serializedPublicKey1: ByteArray, otherSerializedPublicKey2: ByteArray) : Int {
    val publicKey1 = ECPublicKey(serializedPublicKey1)
    val publicKey2 = ECPublicKey(otherSerializedPublicKey2)
    return publicKey1.compareTo(publicKey2)
  }
  internal fun publicKeyGetPublicKeyBytes(serializedPublicKey: ByteArray) : ByteArray {
    val publicKey = ECPublicKey(serializedPublicKey)
    return publicKey.publicKeyBytes
  }
  internal fun publicKeyVerify(serializedPublicKey: ByteArray, message : ByteArray, signature : ByteArray) : Boolean {
    val publicKey = ECPublicKey(serializedPublicKey)
    return publicKey.verifySignature(message, signature)
  }
  internal fun identityKeyVerifyAlternateIdentity(serializedIdentityKey: ByteArray, otherPublicKey: ByteArray, message: ByteArray) : Boolean {
    val identityKey = IdentityKey(serializedIdentityKey)
    val otherIdentityKey = IdentityKey(otherPublicKey)
    return identityKey.verifyAlternateIdentity(otherIdentityKey, message)
  }
  internal fun identityKeyPairSignAlternateIdentity(serializedPublicKey: ByteArray, serializedPrivateKey: ByteArray, otherPublicKey: ByteArray) : ByteArray {
    val identityKey = IdentityKey(serializedPublicKey)
    val privateKey = Curve.decodePrivatePoint(serializedPrivateKey)
    val identityKeyPair = IdentityKeyPair(identityKey, privateKey)
    val otherIdentityKey = IdentityKey(otherPublicKey)
    return identityKeyPair.signAlternateIdentity(otherIdentityKey)
  }
  internal fun privateKeySign(serializedPrivateKey: ByteArray, message: ByteArray) : ByteArray {
    val privateKey = Curve.decodePrivatePoint(serializedPrivateKey)
    return privateKey.calculateSignature(message)
  }
  internal fun identityKeyPairSerialize(serializedPublicKey: ByteArray, serializedPrivateKey: ByteArray) : ByteArray {
    val pubKey = IdentityKey(serializedPublicKey)
    val privateKey = Curve.decodePrivatePoint(serializedPrivateKey)
    return IdentityKeyPair(pubKey, privateKey).serialize()
  }
  internal fun identityKeyPairDeserialize(serializedIdentityKeyPair: ByteArray) : List<ByteArray> {
    val identityKeyPair = IdentityKeyPair(serializedIdentityKeyPair)
    return listOf(identityKeyPair.privateKey.serialize(), identityKeyPair.publicKey.serialize())
  }
  internal fun generateKyberKeyPair() : List<ByteArray>   {
    val keypair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
    return listOf(keypair.secretKey.serialize(), keypair.publicKey.serialize())
  }

  internal fun generateKyberRecord(id: Int, timestamp: Long, privateIdentityKey: ByteArray) : ByteArray {
    val keypair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
    val privateKey =  Curve.decodePrivatePoint(privateIdentityKey)
    val signature = privateKey.calculateSignature(keypair.publicKey.serialize())
    val record = KyberPreKeyRecord(id, timestamp, keypair, signature)
    return record.serialize()
  }

  internal fun kyberPreKeyRecordGetId(record: ByteArray) : Int {
    val rec = KyberPreKeyRecord(record)
    return rec.id
  }
  internal fun kyberPreKeyRecordGetPublicKey(record: ByteArray) : ByteArray {
    val rec = KyberPreKeyRecord(record)
    return rec.keyPair.publicKey.serialize()
  }
  internal fun kyberPreKeyRecordGetSecretKey(record: ByteArray) : ByteArray {
      val rec = KyberPreKeyRecord(record)
      return rec.keyPair.secretKey.serialize()
  }
  internal fun kyberPreKeyRecordGetSignature(record: ByteArray) : ByteArray {
    val rec = KyberPreKeyRecord(record)
    return rec.signature
  }
  internal fun kyberPreKeyRecordGetTimestamp(record: ByteArray): Long {
    val rec = KyberPreKeyRecord(record)
    return rec.timestamp
  }
   // we are passing some arguments in array and receiving them as pairs for reducing the number of parameters to >= 8. we can clean it up further by putting it in a Record class whih is expo's max limit due to the limitations of generics in both Swift and Kotlin because this component must be implemented separately for each.
  internal fun createAndProcessPreKeyBundle(
    registrationData: Pair<String, Int>,
    preKeyData: Pair<Int, String>,
    signedPreKeyData: Pair<Int, String>,
    base64SignedPreKeySignature: String,
    base64IdentityKey: String,
    ownerIdentityData: OwnerData,
    kyberPreKeyData: Pair<Int, String>?,
    base64KyberPreKeySignature: String?
  ) : List<SerializedAddressedKeys> {
     val (base64OwnerKeypair, ownerRegistrationId) = ownerIdentityData
       val ownerKeypair = Base64.decode(base64OwnerKeypair, Base64.NO_WRAP)
       val ownerIdentityKey = IdentityKeyPair(ownerKeypair)
     val (address, registrationId) = registrationData
     val (preKeyId, base64PreKeyPublic) = preKeyData
     val (serviceId, deviceId) = getDeviceIdAndServiceId(address)
     val (signedPreKeyId, base64SignedPreKeyPublic) = signedPreKeyData
     val signedPreKeyPublic = Base64.decode(base64SignedPreKeyPublic, Base64.NO_WRAP)
     val signedPublicPreKey = ECPublicKey(signedPreKeyPublic)
     val identityKey = Base64.decode(base64IdentityKey, Base64.NO_WRAP)
     val idKey = IdentityKey(identityKey)
       val preKeyPublic = Base64.decode(base64PreKeyPublic, Base64.NO_WRAP)
     val publicPreKey = ECPublicKey(preKeyPublic)
     val remoteProtoAddress = SignalProtocolAddress(serviceId, deviceId)

     val store = InMemorySignalProtocolStoreWithPrekeysList(ownerIdentityKey, ownerRegistrationId)
     val sessionBuilder = SessionBuilder(store, remoteProtoAddress)
    val signedPreKeySignature = Base64.decode(base64SignedPreKeySignature, Base64.NO_WRAP)
     if (kyberPreKeyData !== null && base64KyberPreKeySignature !== null) {
       val (keyId, base64KyberPreKeyPublic) = kyberPreKeyData
         val kyberPreKeyPublic = Base64.decode(base64KyberPreKeyPublic, Base64.NO_WRAP)
       val pubKey = KEMPublicKey(kyberPreKeyPublic)
       val kyberPreKeySignature = Base64.decode(base64KyberPreKeySignature, Base64.NO_WRAP)
       val bundle = PreKeyBundle(
         registrationId,
         deviceId,
         preKeyId,
         publicPreKey,
         signedPreKeyId,
         signedPublicPreKey,
         signedPreKeySignature,
         idKey,
         keyId,
         pubKey,
         kyberPreKeySignature
       )
       sessionBuilder.process(bundle)
     } else {

       val noKyberBundle = PreKeyBundle(
         registrationId,
         deviceId,
         preKeyId,
         publicPreKey,
         signedPreKeyId,
         signedPublicPreKey,
         signedPreKeySignature,
         idKey,
       )
       sessionBuilder.process(noKyberBundle)
     }
     val updatedInMemorySessionStore = updateSessionStoreStateFromInMemoryProtocolStore(store, remoteProtoAddress)
     val updatedInMemoryIdentityStore = updateIdentityStoreStateFromInMemoryProtocolStore(store, remoteProtoAddress)
     return listOf(updatedInMemorySessionStore, updatedInMemoryIdentityStore)
   }

   internal fun signedPreKeyRecordNew(id: Int, timestamp: Long, serializedPublicKey: ByteArray, serializedPrivateKey: ByteArray, signature: ByteArray) : ByteArray {
     val publicKey = ECPublicKey(serializedPublicKey)
     val privateKey = Curve.decodePrivatePoint(serializedPrivateKey)
     val keyPair = ECKeyPair(publicKey, privateKey)
     return SignedPreKeyRecord(id, timestamp, keyPair, signature).serialize()
   }
   internal fun signedPreKeyRecordGetId(record: ByteArray) : Int {
     val rec = SignedPreKeyRecord(record)
     return rec.id
   }
    internal fun signedPreKeyRecordGetPrivateKey(record: ByteArray) : ByteArray {
      val rec = SignedPreKeyRecord(record)
      return rec.keyPair.privateKey.serialize()
    }
    internal fun signedPreKeyRecordGetPublicKey(record: ByteArray) : ByteArray {
      val rec = SignedPreKeyRecord(record)
      return rec.keyPair.publicKey.serialize()
    }
    internal fun signedPreKeyRecordGetSignature(record: ByteArray) : ByteArray {
      val rec = SignedPreKeyRecord(record)
      return rec.signature
    }
    internal fun signedPreKeyRecordGetTimestamp(record: ByteArray) : Long {
      val rec = SignedPreKeyRecord(record)
      return rec.timestamp
    }

    internal fun preKeyRecordNew(id: Int, serializedPublicKey: ByteArray, serializedPrivateKey: ByteArray) : ByteArray {
        val publicKey = ECPublicKey(serializedPublicKey)
        val privateKey = Curve.decodePrivatePoint(serializedPrivateKey)
        val keyPair = ECKeyPair(publicKey, privateKey)
        return PreKeyRecord(id, keyPair).serialize()
    }
    internal fun preKeyRecordGetId(record: ByteArray) : Int {
        val rec = PreKeyRecord(record)
        return rec.id
    }
    internal fun preKeyRecordGetPrivateKey(record: ByteArray) : ByteArray {
        val rec = PreKeyRecord(record)
        return rec.keyPair.privateKey.serialize()
    }
    internal fun preKeyRecordGetPublicKey(record: ByteArray) : ByteArray {
        val rec = PreKeyRecord(record)
        return rec.keyPair.publicKey.serialize()
    }

    internal fun sessionRecordArchiveCurrentState(record: ByteArray) : ByteArray {
      val rec = SessionRecord(record)
      rec.archiveCurrentState()
      return rec.serialize()
    }
    internal fun sessionRecordGetLocalRegistrationId(record: ByteArray) : Int {
      val rec = SessionRecord(record)
      return rec.localRegistrationId
    }
    internal fun sessionRecordGetRemoteRegistrationId(record: ByteArray) : Int {
      val rec = SessionRecord(record)
      return rec.remoteRegistrationId
    }
    internal fun sessionRecordHasUsableSenderChain(record: ByteArray, now: Long) : Boolean {
      val rec = SessionRecord(record)
      return rec.hasSenderChain(Instant.ofEpochMilli(now))
    }
    internal fun sessionRecordCurrentRatchetKeyMatches(record: ByteArray, pubKey : ByteArray) : Boolean {
      val ecPublicKey = ECPublicKey(pubKey)
      val rec = SessionRecord(record)
      return rec.currentRatchetKeyMatches(ecPublicKey)
    }
    internal fun sessionCipherEncryptMessage(
        base64Message: String,
        address: String,
        sessionStoreState: SerializedAddressedKeys,
        identityKeyState: IdentityStoreData,
        now: Long
    ) : List<Any> {
        val (serviceId, deviceId) = getDeviceIdAndServiceId(address)
        val remoteProtoAddress = SignalProtocolAddress(serviceId, deviceId)
        val (base64IdentityKey, ownerData) = identityKeyState
        val (base64OwnerKeypair, ownerRegistrationId) = ownerData
        val ownerKeypair = IdentityKeyPair(Base64.decode(base64OwnerKeypair, Base64.NO_WRAP))
        val identityKey = IdentityKey(Base64.decode(base64IdentityKey, Base64.NO_WRAP))
        val store = InMemorySignalProtocolStoreWithPrekeysList(ownerKeypair, ownerRegistrationId)
        store.saveIdentity(remoteProtoAddress, identityKey)
        for ((key, value) in sessionStoreState) {
            val (inStoreName, inStoreDeviceId) = getDeviceIdAndServiceId(key)
            val keyBuffer = Base64.decode(value, Base64.NO_WRAP)
            val protoAddress = SignalProtocolAddress(inStoreName, inStoreDeviceId)
            store.storeSession(protoAddress, SessionRecord(keyBuffer))
        }
        val sessionCipher = SessionCipher(store, remoteProtoAddress)
        val msg = Base64.decode(base64Message, Base64.NO_WRAP)
                val cipher = sessionCipher.encrypt(msg, Instant.ofEpochMilli(now))
        val updatedInMemorySessionStore = updateSessionStoreStateFromInMemoryProtocolStore(store, remoteProtoAddress)
        val updatedInMemoryIdentityStore = updateIdentityStoreStateFromInMemoryProtocolStore(store, remoteProtoAddress)
        return listOf(listOf(cipher.serialize(), cipher.type), listOf(updatedInMemorySessionStore, updatedInMemoryIdentityStore))
    }
//    internal fun SessionCipher_DecryptPreKeySignalMessage(
//        message: Long,
//        address: StringifiedProtocolAddress,
//        idData: OwnerData,
//        prekeyStoreState: SerializedAddressedKeys,
//        signedPrekeyStoreState: SerializedAddressedKeys,
//        kyberPrekeys: SerializedAddressedKeys
//    ) : Pair<ByteArray, Array<SerializedAddressedKeys>> {
//        val (keypair, registrationId) = idData
//        val inMemoryIdentityKeyStore = InMemoryIdentityKeyStore(IdentityKeyPair(Base64.decode(keypair, Base64.NO_WRAP)), registrationId)
//        val protoAddressHandle = address.toLong()
//        val inMemorySessionStore = InMemorySessionStore()
//        var inMemorySignedPrekeyStore = InMemorySignedPreKeyStore()
//        for ((keyId, value) in signedPrekeyStoreState) {
//            val keyBuffer = Base64.decode(value, Base64.NO_WRAP)
//            inMemorySignedPrekeyStore.storeSignedPreKey(keyId.toInt(), SignedPreKeyRecord(keyBuffer))
//        }
//        var inMemoryKyberPreKeyStore = InMemoryKyberPreKeyStore()
//        for ((keyId, value) in kyberPrekeys) {
//            val keyBuffer = Base64.decode(value, Base64.NO_WRAP)
//            inMemoryKyberPreKeyStore.storeKyberPreKey(keyId.toInt(), KyberPreKeyRecord(keyBuffer))
//        }
//        var inMemoryPreKeyStore = InMemoryPreKeyStoreWithList()
//        for ((keyId, value) in prekeyStoreState) {
//            val keyBuffer = Base64.decode(value, Base64.NO_WRAP)
//            inMemoryPreKeyStore.storePreKey(keyId.toInt(), PreKeyRecord(keyBuffer))
//        }
//        val msg = Native.SessionCipher_DecryptPreKeySignalMessage(
//            message,
//            protoAddressHandle,
//            inMemorySessionStore,
//            inMemoryIdentityKeyStore,
//            inMemoryPreKeyStore,
//            inMemorySignedPrekeyStore,
//            inMemoryKyberPreKeyStore
//        )
//        val protoAddress = SignalProtocolAddress(protoAddressHandle)
//        val updatedSession = updateSessionStoreStateFromInMemoryProtocolStore(inMemorySessionStore, protoAddress)
//        val updatedId = updateIdentityStoreStateFromInMemoryProtocolStore(inMemoryIdentityKeyStore, protoAddress)
//        val updatedPreKeyStore = updatePreKeyStoreStateFromInMemoryProtocolStore(inMemoryPreKeyStore)
//        val updatedSignedPreKeyStore = updateSignedPreKeyStoreStateFromInMemoryProtocolStore(inMemorySignedPrekeyStore)
//        val updatedKyberPreKeyStore = updateKyberPreKeyStoreStateFromInMemoryProtocolStore(inMemoryKyberPreKeyStore)
//        return Pair(msg, arrayOf(updatedSession, updatedId, updatedPreKeyStore, updatedSignedPreKeyStore))
//    }
//    const [
//    msg,
//    [
//    updatedSessionStore,
//    updatedIdentityStore,
//    updatedPrekeyStore,
//    updatedSignedPrekeyStore,
//    ],
//    ] = ReactNativeLibsignalClientModule.SessionCipher_DecryptPreKeySignalMessage(
//    message._nativeHandle,
//    String(address._nativeHandle),
//    identityStoreInitializer,
//    prekeyStoreState,
//    signedPrekeyStoreState,
//    kyberPrekeyStoreState
//    )

    internal fun sessionCipherDecryptSignalMessage(
        serializedMessage: ByteArray,
        address: String,
        sessionStoreState: SerializedAddressedKeys,
        identityKeyState: IdentityStoreData,
    ) : List<Any> {
        val (serviceId, deviceId) = getDeviceIdAndServiceId(address)
        val remoteProtoAddress = SignalProtocolAddress(serviceId, deviceId)
        val (base64IdentityKey, ownerData) = identityKeyState
        val (base64OwnerKeypair, ownerRegistrationId) = ownerData
        val ownerKeypair = IdentityKeyPair(Base64.decode(base64OwnerKeypair, Base64.NO_WRAP))
        val identityKey = IdentityKey(Base64.decode(base64IdentityKey, Base64.NO_WRAP))
        val store = InMemorySignalProtocolStoreWithPrekeysList(ownerKeypair, ownerRegistrationId)
        store.saveIdentity(remoteProtoAddress, identityKey)
        for ((key, value) in sessionStoreState) {
            val (inStoreName, inStoreDeviceId) = getDeviceIdAndServiceId(key)
            val keyBuffer = Base64.decode(value, Base64.NO_WRAP)
            val protoAddress = SignalProtocolAddress(inStoreName, inStoreDeviceId)
            store.storeSession(protoAddress, SessionRecord(keyBuffer))
        }
        val sessionCipher = SessionCipher(store, remoteProtoAddress)
        val message = SignalMessage(serializedMessage)
        val plaintext = sessionCipher.decrypt(message)
        val updatedInMemorySessionStore = updateSessionStoreStateFromInMemoryProtocolStore(store, remoteProtoAddress)
        val updatedInMemoryIdentityStore = updateIdentityStoreStateFromInMemoryProtocolStore(store, remoteProtoAddress)
        return listOf(plaintext, listOf(updatedInMemorySessionStore, updatedInMemoryIdentityStore))
    }
    internal fun sessionCipherDecryptPreKeySignalMessage(
        serializedMessage: ByteArray,
        address: String,
        ownerIdentityData: OwnerData,
        prekeyStoreState: SerializedAddressedKeys,
        signedPrekeyStoreState: SerializedAddressedKeys,
        kyberPrekeyStoreState: SerializedAddressedKeys
    ) : List<Any> {
        val (serviceId, deviceId) = getDeviceIdAndServiceId(address)
        val remoteProtoAddress = SignalProtocolAddress(serviceId, deviceId)
        val (base64OwnerKeypair, ownerRegistrationId) = ownerIdentityData
        val ownerKeypair = IdentityKeyPair(Base64.decode(base64OwnerKeypair, Base64.NO_WRAP))
        val store = InMemorySignalProtocolStoreWithPrekeysList(ownerKeypair, ownerRegistrationId)
        for ((key, value) in prekeyStoreState) {
            val keyBuffer = Base64.decode(value, Base64.NO_WRAP)
            store.storePreKey(key.toInt(), PreKeyRecord(keyBuffer))
        }
        for ((key, value) in signedPrekeyStoreState) {
            val keyBuffer = Base64.decode(value, Base64.NO_WRAP)
            store.storeSignedPreKey(key.toInt(), SignedPreKeyRecord(keyBuffer))
        }
        for ((key, value) in kyberPrekeyStoreState) {
            val keyBuffer = Base64.decode(value, Base64.NO_WRAP)
            store.storeKyberPreKey(key.toInt(), KyberPreKeyRecord(keyBuffer))
        }
        val sessionCipher = SessionCipher(store, remoteProtoAddress)
        val message = PreKeySignalMessage(serializedMessage)
        val plaintext = sessionCipher.decrypt(message)
        val updatedInMemorySessionStore = updateSessionStoreStateFromInMemoryProtocolStore(store, remoteProtoAddress)
        val updatedInMemoryIdentityStore = updateIdentityStoreStateFromInMemoryProtocolStore(store, remoteProtoAddress)
        val updatedPreKeyStore = updatePreKeyStoreStateFromInMemoryProtocolStore(store)
        val updatedSignedPreKeyStore = updateSignedPreKeyStoreStateFromInMemoryProtocolStore(store)
        val updatedKyberPreKeyStore = updateKyberPreKeyStoreStateFromInMemoryProtocolStore(store)
        return listOf(plaintext, listOf(updatedInMemorySessionStore, updatedInMemoryIdentityStore, updatedPreKeyStore, updatedSignedPreKeyStore, updatedKyberPreKeyStore))
    }

    internal fun plaintextContentFromDecryptionErrorMessage(message: ByteArray) : ByteArray {
        val decryptionErrorMsg = DecryptionErrorMessage(message)
        val plaintextContent = PlaintextContent(decryptionErrorMsg)
        return plaintextContent.serialize()
    }
    internal fun plaintextContentGetBody(message: ByteArray) : ByteArray {
        val plaintextContent = PlaintextContent(message)
        return plaintextContent.body
    }

    internal fun decryptionErrorMessageForOriginalMessage(originalBytes: ByteArray, messageType: Int, timestamp: Long, originalSenderDeviceId: Int) : ByteArray {
        return DecryptionErrorMessage.forOriginalMessage(originalBytes, messageType, timestamp, originalSenderDeviceId).serialize()
    }
    internal fun decryptionErrorMessageExtractFromSerializedContent(serializedContent: ByteArray) : ByteArray {
        val content = DecryptionErrorMessage.extractFromSerializedContent(serializedContent)
        return content.serialize()
    }
    internal fun decryptionErrorMessageGetTimestamp(serializedContent: ByteArray) : Long {
        val content = DecryptionErrorMessage(serializedContent)
        return content.timestamp
    }
    internal fun decryptionErrorMessageGetDeviceId(serializedContent: ByteArray) : Int {
        val content = DecryptionErrorMessage(serializedContent)
        return content.deviceId
    }
    internal fun decryptionErrorMessageGetRatchetKey(serializedContent: ByteArray) : ByteArray? {
        var ecPublicKey : ByteArray? = null
        val content = DecryptionErrorMessage(serializedContent)
        if (content.ratchetKey.isPresent) {
            ecPublicKey = content.ratchetKey.get().serialize()
        }
        return ecPublicKey
    }
    // this is not used anywhere in app but is useful for testing things separately. here as a reference
//    internal fun signalMessageNew(
//        messageVersion: Int,
//        serializedMacKey: ByteArray,
//        serializedSenderRatchetKey: ByteArray,
//        counter: Int,
//        previousCounter: Int,
//        ciphertext: ByteArray,
//        serializedSenderIdentityKey: ByteArray,
//        serializedReceiverIdentityKey: ByteArray
//    ) : ByteArray {
//        val macKey = SecretKeySpec(serializedMacKey, "HmacSHA256")
//        val senderRatchetKey = ECPublicKey(serializedSenderRatchetKey)
//        val senderIdentityKey = ECPublicKey(serializedSenderIdentityKey)
//        val receiverIdentityKey = ECPublicKey(serializedReceiverIdentityKey)
//        return SignalMessage(
//            Native.SignalMessage_New(
//                messageVersion,
//                macKey.encoded,
//                senderRatchetKey.unsafeNativeHandleWithoutGuard(),
//                counter,
//                previousCounter,
//                ciphertext,
//                senderIdentityKey.unsafeNativeHandleWithoutGuard(),
//                receiverIdentityKey.unsafeNativeHandleWithoutGuard()
//            )
//        ).serialize()
//    }
    internal fun signalMessageGetBody(serializedMessage: ByteArray) : ByteArray {
        val message = SignalMessage(serializedMessage)
        return message.body
    }
    internal fun signalMessageGetCounter(serializedMessage: ByteArray) : Int {
        val message = SignalMessage(serializedMessage)
        return message.counter
    }
    internal fun signalMessageGetMessageVersion(serializedMessage: ByteArray) : Int {
        val message = SignalMessage(serializedMessage)
        return message.messageVersion
    }
    internal fun signalMessageVerifyMac(serializedMessage: ByteArray, serializedSenderIdentityKey: ByteArray, serializedReceiverIdentityKey: ByteArray, serializedMacKey: ByteArray) : Boolean {
        return try {
            val message = SignalMessage(serializedMessage)
            val senderIdentityKey = IdentityKey(serializedSenderIdentityKey)
            val receiverIdentityKey = IdentityKey(serializedReceiverIdentityKey)
            val macKey = SecretKeySpec(serializedMacKey, "HmacSHA256")
            message.verifyMac(senderIdentityKey, receiverIdentityKey, macKey)
            true
        } catch (e: InvalidMessageException) {
            false
        } catch (e: InvalidKeyException) {
            false
        }
    }

    internal fun preKeySignalMessageGetPreKeyId(serializedMessage: ByteArray) : Int? {
        var optionalPreKeyId : Int? = null
        val message = PreKeySignalMessage(serializedMessage)
        if (message.preKeyId.isPresent) {
            optionalPreKeyId = message.preKeyId.get()
        }
        return optionalPreKeyId
    }
    internal fun preKeySignalMessageGetRegistrationId(serializedMessage: ByteArray) : Int {
        val message = PreKeySignalMessage(serializedMessage)
        return message.registrationId
    }
    internal fun preKeySignalMessageGetSignedPreKeyId(serializedMessage: ByteArray) : Int {
        val message = PreKeySignalMessage(serializedMessage)
        return message.signedPreKeyId
    }
    internal fun preKeySignalMessageGetVersion(serializedMessage: ByteArray) : Int {
        val message = PreKeySignalMessage(serializedMessage)
        return message.messageVersion
    }

    internal fun senderKeyMessageGetCipherText(serializedMessage: ByteArray) : ByteArray {
        val message = SenderKeyMessage(serializedMessage)
        return message.cipherText
    }
    internal fun senderKeyMessageGetIteration(serializedMessage: ByteArray) : Int {
        val message = SenderKeyMessage(serializedMessage)
        return message.iteration
    }
    internal fun senderKeyMessageGetChainId(serializedMessage: ByteArray) : Int {
        val message = SenderKeyMessage(serializedMessage)
        return message.chainId
    }
    internal fun senderKeyMessageGetDistributionId(serializedMessage: ByteArray) : String {
        val message = SenderKeyMessage(serializedMessage)
        return message.distributionId.toString()
    }
    internal fun senderKeyMessageVerifySignature(serializedMessage: ByteArray, serializedSenderIdentityKey: ByteArray) : Boolean {
        return try {
            val message = SenderKeyMessage(serializedMessage)
            val senderIdentityKey = ECPublicKey(serializedSenderIdentityKey)
            message.verifySignature(senderIdentityKey)
            true
        } catch (e: InvalidMessageException) {
            false
        } catch (e: InvalidKeyException) {
            false
        }
    }

    internal fun hkdfDeriveSecrets(
        outputLength: Int,
        keyMaterial: ByteArray,
        label: ByteArray,
        salt: ByteArray?
    ) : ByteArray {
        return HKDF.deriveSecrets( keyMaterial, salt, label, outputLength)
    }

    internal fun senderCertificateGetCertificate(serializedCertificate: ByteArray) : ByteArray {
        val certificate = SenderCertificate(serializedCertificate)
        return certificate.certificate
    }
    internal fun senderCertificateGetSignature(serializedCertificate: ByteArray) : ByteArray {
        val certificate = SenderCertificate(serializedCertificate)
        return certificate.signature
    }
    internal fun senderCertificateGetExpiration(serializedCertificate: ByteArray) : Long {
        val certificate = SenderCertificate(serializedCertificate)
        return certificate.expiration
    }
    internal fun senderCertificateGetKey(serializedCertificate: ByteArray) : ByteArray {
        val certificate = SenderCertificate(serializedCertificate)
        return certificate.key.serialize()
    }
    internal fun senderCertificateGetSenderE164(serializedCertificate: ByteArray) : String? {
        val certificate = SenderCertificate(serializedCertificate)
        var senderE164 : String? = null
        if (certificate.senderE164.isPresent) {
            senderE164 = certificate.senderE164.get()
        }
        return senderE164
    }
    internal fun senderCertificateGetSenderUuid(serializedCertificate: ByteArray) : String {
        val certificate = SenderCertificate(serializedCertificate)
        return certificate.senderUuid.toString()
    }
    internal fun senderCertificateGetDeviceId(serializedCertificate: ByteArray) : Int {
        val certificate = SenderCertificate(serializedCertificate)
        return certificate.senderDeviceId
    }
    internal fun senderCertificateGetServerCertificate(serializedCertificate: ByteArray) : ByteArray {
        val certificate = SenderCertificate(serializedCertificate)
        return certificate.signer.serialized
    }
    internal fun senderCertificateValidate(trustRoot: ByteArray, serializedCertificate: ByteArray, timestamp: Long) : Boolean {
                    val certificate = SenderCertificate(serializedCertificate)
            val publicKey = ECPublicKey(trustRoot)
        val certificateValidator = CertificateValidator(publicKey)
        try {
            certificateValidator.validate(certificate, timestamp)
            return true
        } catch (e: InvalidCertificateException) {
            return false
        }
    }

    internal fun serverCertificateGetCertificate(serializedCertificate: ByteArray) : ByteArray {
        val certificate = ServerCertificate(serializedCertificate)
        return certificate.certificate
    }
    internal fun serverCertificateGetKey(serializedCertificate: ByteArray) : ByteArray {
        val certificate = ServerCertificate(serializedCertificate)
        return certificate.key.serialize()
    }
    internal fun serverCertificateGetKeyId(serializedCertificate: ByteArray) : Int {
        val certificate = ServerCertificate(serializedCertificate)
        return certificate.keyId
    }
    internal fun serverCertificateGetSignature(serializedCertificate: ByteArray) : ByteArray {
        val certificate = ServerCertificate(serializedCertificate)
        return certificate.signature
    }

    internal fun senderKeyDistributionMessageGetChainKey(serializedMessage: ByteArray) : ByteArray {
        val message = SenderKeyDistributionMessage(serializedMessage)
        return message.chainKey
    }
    internal fun senderKeyDistributionMessageGetIteration(serializedMessage: ByteArray) : Int {
        val message = SenderKeyDistributionMessage(serializedMessage)
        return message.iteration
    }
    internal fun senderKeyDistributionMessageGetChainId(serializedMessage: ByteArray) : Int {
        val message = SenderKeyDistributionMessage(serializedMessage)
        return message.chainId
    }
    internal fun senderKeyDistributionMessageGetDistributionId(serializedMessage: ByteArray) : String {
        val message = SenderKeyDistributionMessage(serializedMessage)
        return message.distributionId.toString()
    }

//    export async function processSenderKeyDistributionMessage(
//    sender: ProtocolAddress,
//    message: SenderKeyDistributionMessage,
//    store: SenderKeyStore
//    ): Promise<void> {
//        const distributionId = message.distributionId()
//        const newSenderKeyRecord =
//        await ReactNativeLibsignalClientModule.senderKeyDistributionMessageProcess(
//                sender.toString(),
//        message.serialized,
//        await getCurrentKeyHandle(sender, distributionId, store)
//        )
//        store.saveSenderKey(sender, distributionId, newSenderKeyRecord)
//    }
    internal fun senderKeyDistributionMessageProcess(
        senderAddress: String,
        serializedMessage: ByteArray,
        currentSerializedKey: ByteArray
    ) : ByteArray {
        val (serviceId, deviceId) = getDeviceIdAndServiceId(senderAddress)
        val protoAddress = SignalProtocolAddress(serviceId, deviceId)
        val message = SenderKeyDistributionMessage(serializedMessage)
        val senderKey = SenderKeyRecord(currentSerializedKey)
        val senderKeyStore = InMemorySenderKeyStore()
        senderKeyStore.storeSenderKey(protoAddress, message.distributionId,  senderKey)

        val groupSessionBuilder = GroupSessionBuilder(senderKeyStore)
        groupSessionBuilder.process(protoAddress,message)
        val newSenderKeyRecord = senderKeyStore.loadSenderKey(protoAddress, message.distributionId)
        return newSenderKeyRecord.serialize()
    }

    internal fun unidentifiedSenderMessageContentGetContents(serializedContent: ByteArray) : ByteArray {
        val content = UnidentifiedSenderMessageContent(serializedContent)
        return content.content
    }
    internal fun unidentifiedSenderMessageContentGetMsgType(serializedContent: ByteArray) : Int {
        val content = UnidentifiedSenderMessageContent(serializedContent)
        return content.type
    }
    internal fun unidentifiedSenderMessageContentGetSenderCert(serializedContent: ByteArray) : ByteArray {
        val content = UnidentifiedSenderMessageContent(serializedContent)
        return content.senderCertificate.serialized
    }
    internal fun unidentifiedSenderMessageContentGetContentHint(serializedContent: ByteArray) : Int {
        val content = UnidentifiedSenderMessageContent(serializedContent)
        return content.contentHint
    }
    internal fun unidentifiedSenderMessageContentGetGroupId(serializedContent: ByteArray) : ByteArray {
        val content = UnidentifiedSenderMessageContent(serializedContent)
        return content.groupId.orElse(ByteArray(0))
    }

    internal fun sealedSenderEncrypt(destAddress: String, unidentifiedContent: ByteArray, identityKeyState: IdentityStoreData): ByteArray {
        val (serviceId, deviceId) = getDeviceIdAndServiceId(destAddress)
        val protoAddress = SignalProtocolAddress(serviceId, deviceId)

        val (base64IdentityKey, ownerData) = identityKeyState
        val (base64OwnerKeypair, ownerRegistrationId) = ownerData
        val ownerKeypair = IdentityKeyPair(Base64.decode(base64OwnerKeypair, Base64.NO_WRAP))
        val identityKey = IdentityKey(Base64.decode(base64IdentityKey, Base64.NO_WRAP))
        val store = InMemorySignalProtocolStoreWithPrekeysList(ownerKeypair, ownerRegistrationId)
        store.saveIdentity(protoAddress, identityKey)

        val sessCipher = SealedSessionCipher(store, UUID.randomUUID(), "", 1)

        val content = UnidentifiedSenderMessageContent(unidentifiedContent)
        val enccontent = sessCipher.encrypt(protoAddress, content)

        return enccontent
    }

    internal fun sealedSenderDecryptToUsmc(cipherText: ByteArray, ownerData: OwnerData) : ByteArray {
        val (base64OwnerKeypair, ownerRegistrationId) = ownerData
        val ownerKeypair = IdentityKeyPair(Base64.decode(base64OwnerKeypair, Base64.NO_WRAP))

        val sigProtocStore = InMemorySignalProtocolStore(ownerKeypair, ownerRegistrationId)

        return UnidentifiedSenderMessageContent(org.signal.libsignal.internal.Native.SealedSessionCipher_DecryptToUsmc(cipherText, sigProtocStore)).serialized
    }

    internal fun generateRegistrationId(): Int {
        return KeyHelper.generateRegistrationId(false)
    }

    internal fun serverPublicParamsVerifySignature(serializedSrvPubParams: ByteArray, msg: ByteArray, sig: ByteArray) : Boolean {
        val svpublicParams = ServerPublicParams(serializedSrvPubParams)
        val signature = NotarySignature(sig)

        try {
            svpublicParams.verifySignature(msg, signature)
            return true
        } catch (e: VerificationFailedException) {
            return false
        }
    }

    internal fun groupPublicParamsGetGroupIdentifier(serializedGpPubParams: ByteArray) : ByteArray {
        val groupPublicParams = GroupPublicParams(serializedGpPubParams)
        return groupPublicParams.groupIdentifier.serialize()
    }

    internal fun groupSecretParamsGenerateDeterministic(rand: ByteArray) : ByteArray {
        val groupSecretParams = GroupSecretParams.generate(SecureRandom(rand))

        return groupSecretParams.serialize()
    }

    internal fun groupSecretParamsDeriveFromMasterKey(serializedGpMasterKey: ByteArray) : ByteArray {
        val masterKey = GroupMasterKey(serializedGpMasterKey)
        return GroupSecretParams.deriveFromMasterKey(masterKey).serialize()
    }

    internal fun groupSecretParamsGetPublicParams(gpSecParams: ByteArray) : ByteArray {
        val groupSecretParams = GroupSecretParams(gpSecParams)
        return groupSecretParams.publicParams.serialize()
    }

    internal fun groupSecretParamsGetMasterKey(gpSecParams: ByteArray) : ByteArray {
        val groupSecretParams = GroupSecretParams(gpSecParams)
        return groupSecretParams.masterKey.serialize()
    }

    internal fun generateRandomBytes(len: Int) : ByteArray {
        val srandom = SecureRandom()
        val random = ByteArray(len)

        srandom.nextBytes(random)

        return random
    }

    internal fun profileKeyGetCommitment(serializedProfileKey: ByteArray, fixedWidthAci: ByteArray) : ByteArray {
        val pk = ProfileKey(serializedProfileKey)
        val aci = Aci.parseFromFixedWidthBinary(fixedWidthAci)

        return pk.getCommitment(aci).serialize()
    }

    internal fun profileKeyGetVersion(serializedProfileKey: ByteArray, fixedWidthAci: ByteArray) : String {
        val pk = ProfileKey(serializedProfileKey)
        val aci = Aci.parseFromFixedWidthBinary(fixedWidthAci)

        return pk.getProfileKeyVersion(aci).serialize()
    }

    internal fun profileKeyDeriveAccessKey(serializedProfileKey: ByteArray) : ByteArray {
        val pk = ProfileKey(serializedProfileKey)

        return pk.deriveAccessKey()
    }

    internal fun groupSecretParamsEncryptServiceId(sGroupSecretParams: ByteArray, fixedWidthServiceId: ByteArray) : ByteArray {
        val gsp = GroupSecretParams(sGroupSecretParams)
        val sId = ServiceId.parseFromFixedWidthBinary(fixedWidthServiceId)
        val clZkCipher = ClientZkGroupCipher(gsp)

        return clZkCipher.encrypt(sId).serialize()
    }

    internal fun groupSecretParamsDecryptServiceId(sGroupSecretParams: ByteArray, rawCipherText: ByteArray) : ByteArray {
        val gsp = GroupSecretParams(sGroupSecretParams)
        val cipherText = UuidCiphertext(rawCipherText)
        val clZkCipher = ClientZkGroupCipher(gsp)

        return clZkCipher.decrypt(cipherText).toServiceIdFixedWidthBinary()
    }

    internal fun groupSecretParamsEncryptProfileKey(sGroupSecretParams: ByteArray, rawProfileKey: ByteArray, fixedWidthAci: ByteArray) : ByteArray {
        val gsp = GroupSecretParams(sGroupSecretParams)
        val pk = ProfileKey(rawProfileKey)
        val aci = Aci.parseFromFixedWidthBinary(fixedWidthAci)
        val clZkCipher = ClientZkGroupCipher(gsp)

        return clZkCipher.encryptProfileKey(pk, aci).serialize()
    }

    internal fun groupSecretParamsDecryptProfileKey(sGroupSecretParams: ByteArray, rawProfileKeyCipherText: ByteArray, fixedWidthAci: ByteArray) : ByteArray {
        val gsp = GroupSecretParams(sGroupSecretParams)
        val pkct = ProfileKeyCiphertext(rawProfileKeyCipherText)
        val aci = Aci.parseFromFixedWidthBinary(fixedWidthAci)
        val clZkCipher = ClientZkGroupCipher(gsp)

        return clZkCipher.decryptProfileKey(pkct, aci).serialize()
    }

    internal fun groupSecretParamsEncryptBlobWithPaddingDeterministic(sGroupSecretParams: ByteArray, randomNess: ByteArray, plainText: ByteArray, paddingLen: Int) : ByteArray {
        val gsp = GroupSecretParams(sGroupSecretParams)
        val clZkCipher = ClientZkGroupCipher(gsp)

        return clZkCipher.encryptBlob(SecureRandom(randomNess), plainText)
    }

    internal fun groupSecretParamsDecryptBlobWithPadding(sGroupSecretParams: ByteArray, blobCipherText: ByteArray) : ByteArray {
        val gsp = GroupSecretParams(sGroupSecretParams)
        val clZkCipher = ClientZkGroupCipher(gsp)

        return clZkCipher.decryptBlob(blobCipherText)
    }

    internal fun expiringProfileKeyCredentialGetExpirationTime(sExpiringProfileKeyCredential: ByteArray) : Long {
        val expkc = ExpiringProfileKeyCredential(sExpiringProfileKeyCredential)

        return expkc.expirationTime.epochSecond
    }

    internal fun profileKeyCredentialPresentationGetUuidCiphertext(sProfileKeyCredentialPresentation: ByteArray) : ByteArray {
        val pkcp = ProfileKeyCredentialPresentation(sProfileKeyCredentialPresentation)

        return pkcp.uuidCiphertext.serialize()
    }

    internal fun profileKeyCredentialPresentationGetProfileKeyCiphertext(sProfileKeyCredentialPresentation: ByteArray) : ByteArray {
        val pkcp = ProfileKeyCredentialPresentation(sProfileKeyCredentialPresentation)

        return pkcp.profileKeyCiphertext.serialize()
    }

    internal fun profileKeyCredentialRequestContextGetRequest(sProfileKeyCredentialRequestContext: ByteArray) : ByteArray {
        val pkcrc = ProfileKeyCredentialRequestContext(sProfileKeyCredentialRequestContext)

        return pkcrc.request.serialize()
    }

    internal fun serverPublicParamsCreateProfileKeyCredentialRequestContextDeterministic(sServerPublicParams: ByteArray, randomness: ByteArray, fixedWidthAci: ByteArray, sProfileKey: ByteArray) : ByteArray {
        val serverPublicParams = ServerPublicParams(sServerPublicParams)
        val clientZkProfileOperation = ClientZkProfileOperations(serverPublicParams)
        val aci = Aci.parseFromFixedWidthBinary(fixedWidthAci)
        val profileKey = ProfileKey(sProfileKey)
        return clientZkProfileOperation.createProfileKeyCredentialRequestContext(SecureRandom(randomness), aci, profileKey).serialize()
    }

    internal fun serverPublicParamsReceiveExpiringProfileKeyCredential(sServerPublicParams: ByteArray, sProfileKeyCredReqCtx: ByteArray, sExpProfileKeyCredResponse: ByteArray, ts: Long) : ByteArray {
        val serverPublicParams = ServerPublicParams(sServerPublicParams)
        val clientZkProfileOperation = ClientZkProfileOperations(serverPublicParams)
        val pkCredReqCtx = ProfileKeyCredentialRequestContext(sProfileKeyCredReqCtx)
        val pkExpCredResp = ExpiringProfileKeyCredentialResponse(sExpProfileKeyCredResponse)

        return clientZkProfileOperation.receiveExpiringProfileKeyCredential(pkCredReqCtx, pkExpCredResp).serialize()
    }

    internal fun serverPublicParamsCreateExpiringProfileKeyCredentialPresentationDeterministic(sServerPublicParams: ByteArray, randomness: ByteArray, sGpSecParams: ByteArray, sExpProfKeyCred: ByteArray) : ByteArray {
        val serverPublicParams = ServerPublicParams(sServerPublicParams)
        val clientZkProfileOperation = ClientZkProfileOperations(serverPublicParams)
        val groupSecretParams = GroupSecretParams(sGpSecParams)
        val expProfKeyCredential = ExpiringProfileKeyCredential(sExpProfKeyCred)

        return clientZkProfileOperation.createProfileKeyCredentialPresentation(SecureRandom(randomness), groupSecretParams, expProfKeyCredential).serialize()
    }

    internal fun authCredentialPresentationGetUuidCiphertext(sAuthCredPres: ByteArray) : ByteArray {
        val authCredPresentation = AuthCredentialPresentation(sAuthCredPres)

        return authCredPresentation.uuidCiphertext.serialize()
    }

    internal fun authCredentialPresentationGetPniCiphertext(sAuthCredPres: ByteArray) : ByteArray {
        val authCredPresentation = AuthCredentialPresentation(sAuthCredPres)

        return authCredPresentation.pniCiphertext.serialize()
    }

    internal fun authCredentialPresentationGetRedemptionTime(sAuthCredPres: ByteArray) : Long {
        val authCredPresentation = AuthCredentialPresentation(sAuthCredPres)

        return authCredPresentation.redemptionTime.epochSecond
    }

    internal fun serverPublicParamsReceiveAuthCredentialWithPniAsServiceId(sSrvPubParams: ByteArray, fixedWidthAci: ByteArray, fixedWidthPni: ByteArray, redemptionTime: Long, authCredPniResp: ByteArray) : ByteArray {
        val serverPublicParams = ServerPublicParams(sSrvPubParams)
        val clientZkAuthOperation = ClientZkAuthOperations(serverPublicParams)
        val aci = Aci.parseFromFixedWidthBinary(fixedWidthAci)
        val pni = Pni.parseFromFixedWidthBinary(fixedWidthPni)
        val authCredentialPniResponse = AuthCredentialWithPniResponse(authCredPniResp)

        return clientZkAuthOperation.receiveAuthCredentialWithPniAsServiceId(aci, pni, redemptionTime, authCredentialPniResponse).serialize()
    }

    internal fun serverPublicParamsCreateAuthCredentialWithPniPresentationDeterministic(sSrvPubParams: ByteArray, randomness: ByteArray, sGpSecParams: ByteArray, authCredPni: ByteArray) : ByteArray {
        val serverPublicParams = ServerPublicParams(sSrvPubParams)
        val clientZkAuthOperation = ClientZkAuthOperations(serverPublicParams)
        val gpSecretParams = GroupSecretParams(sGpSecParams)
        val authCredentialPni = AuthCredentialWithPni(authCredPni)

        return clientZkAuthOperation.createAuthCredentialPresentation(gpSecretParams, authCredentialPni).serialize()
    }

    internal fun serverSecretParamsGenerateDeterministic(rndm: ByteArray) : ByteArray {
        val srvSecParams = ServerSecretParams.generate(SecureRandom(rndm))

        return srvSecParams.serialize()
    }

    internal fun serverSecretParamsGetPublicParams(sSrvSecParams: ByteArray) : ByteArray {
        val srvSecParams = ServerSecretParams(sSrvSecParams)

        return srvSecParams.publicParams.serialize()
    }

    internal fun serverSecretParamsSignDeterministic(sSrvSecParams: ByteArray, rndm: ByteArray, msg: ByteArray) : ByteArray {
        val srvSecParams = ServerSecretParams(sSrvSecParams)

        return srvSecParams.sign(SecureRandom(rndm), msg).serialize()
    }

    internal fun serverSecretParamsIssueAuthCredentialWithPniAsServiceIdDeterministic(sSrvSecParams: ByteArray, rndm: ByteArray, sAci: ByteArray, sPni: ByteArray, redemptionTime: Long): ByteArray {
        val srvSecParams = ServerSecretParams(sSrvSecParams)
        val serverAuthOp = ServerZkAuthOperations(srvSecParams)
        val aci = Aci.parseFromFixedWidthBinary(sAci)
        val pni = Pni.parseFromFixedWidthBinary(sPni)
        val authCredPniResp = serverAuthOp.issueAuthCredentialWithPniZkc(SecureRandom(rndm), aci, pni, Instant.ofEpochSecond(redemptionTime))

        return authCredPniResp.serialize()
    }

    internal fun serverSecretParamsIssueAuthCredentialWithPniZkcDeterministic(sSrvSecParams: ByteArray, rndm: ByteArray, sAci: ByteArray, sPni: ByteArray, redemptionTime: Long): ByteArray {
        val srvSecParams = ServerSecretParams(sSrvSecParams)
        val serverAuthOp = ServerZkAuthOperations(srvSecParams)
        val aci = Aci.parseFromFixedWidthBinary(sAci)
        val pni = Pni.parseFromFixedWidthBinary(sPni)
        val authCredPniResp = serverAuthOp.issueAuthCredentialWithPniZkc(SecureRandom(rndm), aci, pni, Instant.ofEpochSecond(redemptionTime))

        return authCredPniResp.serialize()
    }

    internal fun serverSecretParamsVerifyAuthCredentialPresentation(sSrvSecParams: ByteArray, sGpPublicParams: ByteArray, sAuthCredPresent: ByteArray, instant: Long) {
        val srvSecParams = ServerSecretParams(sSrvSecParams)
        val serverAuthOp = ServerZkAuthOperations(srvSecParams)
        val gpPubParams = GroupPublicParams(sGpPublicParams)
        val authCredPresentation = AuthCredentialPresentation(sAuthCredPresent)

        serverAuthOp.verifyAuthCredentialPresentation(gpPubParams, authCredPresentation, Instant.ofEpochSecond( instant))
    }

    internal fun groupSecretParamsEncryptCiphertext(sGpSecParams: ByteArray, sServiceId: ByteArray): ByteArray {
        val gpSecParams = GroupSecretParams(sGpSecParams)
        val serviceId = ServiceId.parseFromFixedWidthBinary(sServiceId)
        val clZkGpCipher = ClientZkGroupCipher(gpSecParams)

        return clZkGpCipher.encrypt(serviceId).serialize()
    }

    internal fun serverSecretParamsIssueExpiringProfileKeyCredentialDeterministic(sSrvSecParams: ByteArray, rand: ByteArray, sProfCredRequest: ByteArray, sAci: ByteArray, sProfileKeyCommitment: ByteArray, expiration: Long): ByteArray {
        val SrvSecretParams = ServerSecretParams(sSrvSecParams)
        val SrvProfileOp = ServerZkProfileOperations(SrvSecretParams)
        val profCredRequest = ProfileKeyCredentialRequest(sProfCredRequest)
        val aci = Aci.parseFromFixedWidthBinary(sAci)
        val ProfCommitment = ProfileKeyCommitment(sProfileKeyCommitment)

        return SrvProfileOp.issueExpiringProfileKeyCredential(SecureRandom(rand),  profCredRequest, aci, ProfCommitment, Instant.ofEpochSecond(expiration)).serialize()
    }

    internal fun serverSecretParamsVerifyProfileKeyCredentialPresentation(sSrvSecParams: ByteArray, sGpPublicParams: ByteArray, sProfileKeyCredentialPresentation: ByteArray, instant: Long) {
        val SrvSecretParams = ServerSecretParams(sSrvSecParams)
        val SrvProfileOp = ServerZkProfileOperations(SrvSecretParams)
        val GpPubParams = GroupPublicParams(sGpPublicParams)
        val ProfKeyCredPresentation = ProfileKeyCredentialPresentation(sProfileKeyCredentialPresentation)

        SrvProfileOp.verifyProfileKeyCredentialPresentation(GpPubParams,
            ProfKeyCredPresentation, Instant.ofEpochSecond(instant))
    }

    internal fun Aes256GcmEncrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray, aad: ByteArray?): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            gcmSpec
        )
        if (aad != null) {
            cipher.updateAAD(aad)
        }
        return cipher.doFinal(plaintext)
    }

    internal fun Aes256GcmDecrypt(key: ByteArray, iv: ByteArray, ciphertext: ByteArray, aad: ByteArray?): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            gcmSpec
        )
        if (aad != null) {
            cipher.updateAAD(aad)
        }
        return cipher.doFinal(ciphertext)
    }

    internal fun Aes256CbcEncrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            IvParameterSpec(iv)
        )
        return cipher.doFinal(plaintext)
    }

    internal fun Aes256CbcDecrypt(key: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            IvParameterSpec(iv)
        )
        return cipher.doFinal(ciphertext)
    }

    internal fun Aes256CtrEncrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            IvParameterSpec(iv)
        )
        return cipher.doFinal(plaintext)
    }

    internal fun Aes256CtrDecrypt(key: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            IvParameterSpec(iv)
        )
        return cipher.doFinal(ciphertext)
    }

    internal fun HmacSHA256(key: ByteArray, data: ByteArray): ByteArray? {
        return try {
            val mac = Mac.getInstance("HmacSHA256")
            val secretKey = SecretKeySpec(key, "HmacSHA256")
            mac.init(secretKey)
            mac.doFinal(data)
        } catch (e: Exception) {

            return null
        }
    }

    internal fun ConstantTimeEqual(lhs: ByteArray, rhs: ByteArray): Boolean {
        if (lhs === rhs) return true

        if (lhs.size != rhs.size) return false

        var result = 0
        for (i in lhs.indices) {
            result = result or (lhs[i].toInt() xor rhs[i].toInt())
        }
        return result == 0
    }



    internal fun groupSendFullTokenGetExpiration(sgpfulltoken: ByteArray): Long {
        val gpFullToken = GroupSendFullToken(sgpfulltoken)

        return gpFullToken.expiration.epochSecond
    }

    internal fun groupSendFullTokenVerify(sgpfulltoken: ByteArray, fixedWidthIds: ByteArray, time: Long, gpsenddrivedkp: ByteArray) {
        val gpFullToken = GroupSendFullToken(sgpfulltoken)
        val serviceIds = parseFixedWidthServiceIds(fixedWidthIds)
        val groupSendKeyPair = GroupSendDerivedKeyPair(gpsenddrivedkp)

        gpFullToken.verify(serviceIds, Instant.ofEpochSecond(time), groupSendKeyPair)
    }

    internal fun groupSendTokenToFullToken(sgpsendtoken: ByteArray, expTime: Long): ByteArray {
        val groupSendToken = GroupSendEndorsement.Token(sgpsendtoken)

        return groupSendToken.toFullToken(Instant.ofEpochSecond(expTime)).serialize()
    }

    internal fun groupSendDerivedKeyPairForExpiration(expTime: Long, svSecParams: ByteArray): ByteArray {
        val serverSecParams = ServerSecretParams(svSecParams)

        return GroupSendDerivedKeyPair.forExpiration(Instant.ofEpochSecond(expTime), serverSecParams).serialize()
    }

    internal fun groupSendEndorsementCombine(sendorseMents: List<String>): ByteArray {
        val rr = sendorseMents.map{ se -> Base64.decode(se, 0)}.map { se -> GroupSendEndorsement(se) }

        return GroupSendEndorsement.combine(rr).serialize()
    }

    internal fun groupSendEndorsementRemove(sgpsendendorsement: ByteArray, toRemove: ByteArray): ByteArray {
        val bGroupSendEndorsement = GroupSendEndorsement(sgpsendendorsement)
        val gpseToRemove = GroupSendEndorsement(toRemove)

        return bGroupSendEndorsement.byRemoving(gpseToRemove).serialize()
    }

    internal fun groupSendEndorsementToToken(sgpsendendorsement: ByteArray, sGpSecParams: ByteArray): ByteArray {
        val groupSendEndorsement = GroupSendEndorsement(sgpsendendorsement)

        return groupSendEndorsement.toToken(GroupSecretParams(sGpSecParams)).serialize()
    }

    internal fun groupSendEndorsementsResponseIssueDeterministic(uuidCipherTexts: ByteArray, gpsenddrivedkp: ByteArray, rndm: ByteArray): ByteArray {
        val serviceIds = parseUuidCipherTexts(uuidCipherTexts)
        val groupSendKeyPair = GroupSendDerivedKeyPair(gpsenddrivedkp)

        return GroupSendEndorsementsResponse.issue(serviceIds, groupSendKeyPair, SecureRandom(rndm)).serialize()
    }

    internal fun groupSendEndorsementsResponseGetExpiration(gpSendEndResponse: ByteArray): Long {
        val groupSendEndResponse = GroupSendEndorsementsResponse(gpSendEndResponse)

        return groupSendEndResponse.expiration.epochSecond
    }

    internal fun groupSendEndorsementsResponseReceiveAndCombineWithServiceIds(gpSendEndResponse: ByteArray, svcIds: ByteArray, userId: ByteArray, time: Long, gpSecParams: ByteArray, srvPubParams: ByteArray): List<ByteArray> {
        val groupSendEndResponse = GroupSendEndorsementsResponse(gpSendEndResponse)
        val serviceIds = parseFixedWidthServiceIds(svcIds)
        val userServiceId = Aci.parseFromFixedWidthBinary(userId)
        val localUserIndex = serviceIds.indexOf(userServiceId)
        if (localUserIndex == -1) {
            throw Error("local user not present in the memebers service ids list")
        }

        val groupSecretParams = GroupSecretParams(gpSecParams)
        val serverPublicParams = ServerPublicParams(srvPubParams)
        val endorsements = groupSendEndResponse.receive(serviceIds, userServiceId, Instant.ofEpochSecond(time), groupSecretParams, serverPublicParams).endorsements
        val combined = GroupSendEndorsement.combine(endorsements.slice(0..localUserIndex-1).plus(endorsements.slice(localUserIndex+1..endorsements.size-1))).serialize()

        return endorsements.map { end -> end.serialize() }.plus(combined)
    }

    internal fun groupSendEndorsementsResponseReceiveAndCombineWithCiphertexts(gpSendEndResponse: ByteArray, svcUuidIds: ByteArray, userId: ByteArray, time: Long, srvPubParams: ByteArray): List<ByteArray> {
        val groupSendEndResponse = GroupSendEndorsementsResponse(gpSendEndResponse)
        val serviceIds = parseUuidCipherTexts(svcUuidIds)
        val userServiceId = UuidCiphertext(userId)
        val serverPublicParams = ServerPublicParams(srvPubParams)
        val localUserIndex = serviceIds.indexOf(userServiceId)
        if (localUserIndex == -1) {
            throw Error("local user not present in the memebers service ids list")
        }

        val endorsements = groupSendEndResponse.receive(serviceIds, userServiceId, Instant.ofEpochSecond(time), serverPublicParams).endorsements
        val combined = GroupSendEndorsement.combine(endorsements.slice(0..localUserIndex-1).plus(endorsements.slice(localUserIndex+1..endorsements.size-1))).serialize()

        return endorsements.map { end -> end.serialize() }.plus(combined)
    }

    internal fun unidentifiedSenderMessageContentNew(msgCiphertext: ByteArray, cipherTextType: Int, sSenderCertificate: ByteArray, contentHint: Int, groupId: ByteArray): ByteArray {
        val senderCertificate = SenderCertificate(sSenderCertificate)
        val ciphertextMessage = parseCiphertext(msgCiphertext, cipherTextType)
        val opGroupId: Optional<ByteArray> = if (groupId.isEmpty()) {
            Optional.empty()
        } else {
            Optional.of(groupId)
        }

        return UnidentifiedSenderMessageContent(ciphertextMessage, senderCertificate, contentHint, opGroupId).serialized
    }

    internal fun groupCipherEncryptMessage(senderAddress: String, sDistId: String, msg: ByteArray, sSenderKeyRecord: ByteArray): List<Any> {
        val (serviceId, deviceId) = getDeviceIdAndServiceId(senderAddress)
        val protoAddress = SignalProtocolAddress(serviceId, deviceId)
        val distId = UUID.fromString(sDistId)

        val senderKeyStore = InMemorySenderKeyStore()
        if (sSenderKeyRecord.isNotEmpty()) {
            val sndKeyRec = SenderKeyRecord(sSenderKeyRecord)
            senderKeyStore.storeSenderKey(protoAddress, distId,  sndKeyRec)
        }

        val gpCipher = GroupCipher(senderKeyStore, protoAddress)
        val cipherText = gpCipher.encrypt(distId, msg)

        val newSenderKeyRecord = senderKeyStore.loadSenderKey(protoAddress, distId)

        return listOf(listOf(cipherText.serialize(), cipherText.type), newSenderKeyRecord.serialize())
    }

    internal fun groupCipherDecryptMessage(senderAddress: String, msg: ByteArray, sSenderKeyRecord: ByteArray): List<ByteArray> {
        val (serviceId, deviceId) = getDeviceIdAndServiceId(senderAddress)
        val protoAddress = SignalProtocolAddress(serviceId, deviceId)
        val sndKeyRec = SenderKeyRecord(sSenderKeyRecord)
        val senderKeyMessage = SenderKeyMessage(msg)

        val senderKeyStore = InMemorySenderKeyStore()
        senderKeyStore.storeSenderKey(protoAddress, senderKeyMessage.distributionId,  sndKeyRec)

        val gpCipher = GroupCipher(senderKeyStore, protoAddress)
        val cipherText = gpCipher.decrypt(msg)

        val newSenderKeyRecord = senderKeyStore.loadSenderKey(protoAddress, senderKeyMessage.distributionId)

        return listOf(cipherText, newSenderKeyRecord.serialize())
    }

    internal fun senderKeyDistributionMessageCreate(senderAddress: String, distId: String, sKeyRecord: ByteArray): List<ByteArray> {
        val (serviceId, deviceId) = getDeviceIdAndServiceId(senderAddress)
        val senderProtocolAddress = SignalProtocolAddress(serviceId, deviceId)
        val senderKeyStore = InMemorySenderKeyStore()
        val distributionId = UUID.fromString(distId)
        if (sKeyRecord.isNotEmpty()) {
            val rec = SenderKeyRecord(sKeyRecord)
            senderKeyStore.storeSenderKey(senderProtocolAddress, distributionId, rec)
        }
        val r = GroupSessionBuilder(senderKeyStore)
        val senderKeyDistributionMessage = r.create(senderProtocolAddress, distributionId)
        val updatedRec = senderKeyStore.loadSenderKey(senderProtocolAddress, distributionId)
        val updatedRecSer = Optional.ofNullable(updatedRec).map { v -> v.serialize() }

        return listOf(senderKeyDistributionMessage.serialize(), updatedRecSer.orElse(ByteArray(0)))
    }

    internal fun sealedSenderMultiRecipientEncrypt(ownerIdentityData: OwnerData, srecipients: List<String>, recipientSessions: SerializedAddressedKeys, excludedRecipients: ByteArray, uidentcontent: ByteArray, identityStoreState: List<Pair<String, String>>): ByteArray {
        val messageContent = UnidentifiedSenderMessageContent(uidentcontent)
        val recipients = srecipients.map { v -> getDeviceIdAndServiceId(v) }.map { v -> SignalProtocolAddress(v.first, v.second) }
        val excludedServiceIds = parseFixedWidthServiceIds(excludedRecipients)

        val (base64OwnerKeypair, ownerRegistrationId) = ownerIdentityData
        val ownerKeypair = Base64.decode(base64OwnerKeypair, Base64.NO_WRAP)
        val ownerIdentityKey = IdentityKeyPair(ownerKeypair)
        val sigStore = InMemorySignalProtocolStore(ownerIdentityKey, ownerRegistrationId)
                for (p in identityStoreState) {
                val (serviceid, deviceid) = getDeviceIdAndServiceId(p.first)
                val padd = SignalProtocolAddress(serviceid, deviceid)
                val ident = IdentityKey(        Base64.decode(p.second, Base64.NO_WRAP))
                sigStore.saveIdentity(padd, ident)
        }

        for ((key, value) in recipientSessions) {
            val (inStoreName, inStoreDeviceId) = getDeviceIdAndServiceId(key)
            val keyBuffer = Base64.decode(value, Base64.NO_WRAP)
            val protoAddress = SignalProtocolAddress(inStoreName, inStoreDeviceId)
            sigStore.storeSession(protoAddress, SessionRecord(keyBuffer))
        }

        // random uuid is generated so that we wont panic. don't worry it is not needed in encryption process
        val gpCipher = SealedSessionCipher(sigStore, UUID.randomUUID(), null, ownerRegistrationId)
        return gpCipher.multiRecipientEncrypt(recipients, messageContent, excludedServiceIds)
    }

    internal fun serverCertificateNew(keyId: Int, serverKey: ByteArray, trustKey: ByteArray): ByteArray {
        val trustRoot = ECPrivateKey(trustKey)
        val serverKeyPub = ECPublicKey(serverKey)

        return ServerCertificate(trustRoot, keyId, serverKeyPub).serialized
    }

    internal fun senderCertificateNew(
        localSenderUuid: String,
        senderE164: String,
        senderDeviceId: Int,
        senderKey: ByteArray,
        expiration: Long,
        signerCert: ByteArray,
        signerKey: ByteArray): ByteArray {
        val senderPubKey = ECPublicKey(senderKey)
        val signerCertif = ServerCertificate(signerCert)
        val signerPrivKey = ECPrivateKey(signerKey)

        val senderOpE164 = if (senderE164.isEmpty()) {
            Optional.empty<String>()
        } else {
            Optional.of(senderE164)
        }

        return signerCertif.issue(signerPrivKey, localSenderUuid, senderOpE164, senderDeviceId, senderPubKey, expiration).serialized
    }

    internal fun sealedSenderMultiRecipientMessageForSingleRecipient(msg: ByteArray): ByteArray {
        return org.signal.libsignal.internal.Native.SealedSessionCipher_MultiRecipientMessageForSingleRecipient(msg)
    }

    internal fun backupAuthCredentialRequestContextNew(backupKeyr: ByteArray, acir: String): ByteArray {
        val aci = UUID.fromString(acir)

        return BackupAuthCredentialRequestContext.create(backupKeyr, aci).serialize()
    }

    internal fun backupAuthCredentialRequestContextGetRequest(backupReqCtxRaw: ByteArray): ByteArray {
        return BackupAuthCredentialRequestContext(backupReqCtxRaw).request.serialize()
    }

    internal fun backupAuthCredentialRequestContextReceiveResponse(backupReqCtxRaw: ByteArray, backupResRaw: ByteArray, redemptionTime: Long, genericServerPubParamsRaw: ByteArray): ByteArray {
        return BackupAuthCredentialRequestContext(backupReqCtxRaw).receiveResponse(
            BackupAuthCredentialResponse(backupResRaw),
            Instant.ofEpochSecond(redemptionTime),
            GenericServerPublicParams(genericServerPubParamsRaw)
        ).serialize()
    }

    internal fun backupAuthCredentialRequestIssueDeterministic(backupReqRaw: ByteArray, timestamp: Long, backuplevel: Int, credentialType: Int   , genericServerSecParamsRaw: ByteArray, randomness: ByteArray): ByteArray {
        val req = BackupAuthCredentialRequest(backupReqRaw)

        return req.issueCredential(
            Instant.ofEpochSecond(timestamp),
            BackupLevel.fromValue(backuplevel),
            BackupCredentialType.fromValue(credentialType),
            GenericServerSecretParams((genericServerSecParamsRaw)),
            SecureRandom(randomness)
        ).serialize()
    }

    internal fun backupAuthCredentialPresentationVerify(bckCredPresRaw: ByteArray, timestamp: Long, genericServerSecParamsRaw: ByteArray) {
        val credPres = BackupAuthCredentialPresentation(bckCredPresRaw)

        credPres.verify(Instant.ofEpochSecond(timestamp),  GenericServerSecretParams(genericServerSecParamsRaw))
    }

    internal fun backupAuthCredentialPresentationGetBackupId(bckCredPresRaw: ByteArray): ByteArray {
        val credPres = BackupAuthCredentialPresentation(bckCredPresRaw)

        return credPres.backupId
    }

    internal fun backupAuthCredentialPresentationGetBackupLevel(bckCredPresRaw: ByteArray): Int {
        val credPres = BackupAuthCredentialPresentation(bckCredPresRaw)

        return credPres.backupLevel.toNumber()
    }

    internal fun backupAuthCredentialPresentationGetType(bckCredPresRaw: ByteArray): Int {
        val credPres = BackupAuthCredentialPresentation(bckCredPresRaw)

        return credPres.type.toNumber()
    }

    internal fun backupAuthCredentialPresentDeterministic(bckAuthCredRaw: ByteArray, genericServerPubParamsRaw: ByteArray, randomness: ByteArray): ByteArray {
        val backAuthCred = BackupAuthCredential(bckAuthCredRaw)

        return backAuthCred.present(GenericServerPublicParams(genericServerPubParamsRaw), SecureRandom(randomness)).serialize()
    }

    internal fun backupAuthCredentialGetBackupId(bckAuthCredRaw: ByteArray): ByteArray {
        val backAuthCred = BackupAuthCredential(bckAuthCredRaw)

        return backAuthCred.backupId
    }

    internal fun backupAuthCredentialGetBackupLevel(bckAuthCredRaw: ByteArray): Int {
        val backAuthCred = BackupAuthCredential(bckAuthCredRaw)

        return backAuthCred.backupLevel.toNumber()
    }

    internal fun backupAuthCredentialGetType(bckAuthCredRaw: ByteArray): Int {
        val backAuthCred = BackupAuthCredential(bckAuthCredRaw)

        return backAuthCred.type.toNumber()
    }

    internal fun genericServerSecretParamsGenerateDeterministic(randomness: ByteArray): ByteArray {
      return GenericServerSecretParams.generate(SecureRandom(randomness)).serialize()
    }

    internal fun genericServerSecretParamsGetPublicParams(genericServerSecParamsRaw: ByteArray): ByteArray {
      val genericSecParams = GenericServerSecretParams(genericServerSecParamsRaw)

      return genericSecParams.publicParams.serialize()
    }

  internal fun backupKeyDeriveBackupId(bckKeyRaw: ByteArray, serviceIdBinary: ByteArray): ByteArray {
    val backupKey = BackupKey(bckKeyRaw)
    val serviceId = Aci.parseFromFixedWidthBinary(serviceIdBinary)

    return backupKey.deriveBackupId(serviceId)
  }

  internal fun backupKeyDeriveEcKey(bckKeyRaw: ByteArray, serviceIdBinary: ByteArray): ByteArray {
    val backupKey = BackupKey(bckKeyRaw)
    val serviceId = Aci.parseFromFixedWidthBinary(serviceIdBinary)

    return backupKey.deriveEcKey(serviceId).serialize()
  }

  internal fun backupKeyDeriveLocalBackupMetadataKey(bckKeyRaw: ByteArray): ByteArray {
    val backupKey = BackupKey(bckKeyRaw)

    return backupKey.deriveLocalBackupMetadataKey()
  }

  internal fun backupKeyDeriveMediaId(bckKeyRaw: ByteArray, mediaName: String): ByteArray {
    val backupKey = BackupKey(bckKeyRaw)

    return backupKey.deriveMediaId(mediaName)
  }

  internal fun backupKeyDeriveMediaEncryptionKey(bckKeyRaw: ByteArray, mediaId: ByteArray): ByteArray {
    val backupKey = BackupKey(bckKeyRaw)

    return backupKey.deriveMediaEncryptionKey(mediaId)
  }

  internal fun backupKeyDeriveThumbnailTransitEncryptionKey(bckKeyRaw: ByteArray, mediaId: ByteArray): ByteArray {
    val backupKey = BackupKey(bckKeyRaw)

    return backupKey.deriveThumbnailTransitEncryptionKey(mediaId)
  }

  internal fun accountEntropyPoolGenerate(): String {
    return AccountEntropyPool.generate()
  }

  internal fun accountEntropyPoolIsValid(entPool: String): Boolean {
    return AccountEntropyPool.isValid(entPool)
  }

  internal fun accountEntropyPoolDeriveSvrKey(entPool: String): ByteArray {
    return AccountEntropyPool.deriveSvrKey(entPool)
  }

  internal fun accountEntropyPoolDeriveBackupKey(entPool: String): ByteArray {
    return AccountEntropyPool.deriveBackupKey(entPool).serialize()
  }

  internal fun messageBackupKeyFromAccountEntropyPool(entPool: String, aciBinary: ByteArray): ByteArray {
    val aci = Aci.parseFromFixedWidthBinary(aciBinary)
    val backupKey = MessageBackupKey(entPool, aci)

    return backupKey.serialize()
  }

  internal fun messageBackupKeyFromBackupKeyAndBackupId(bckKeyRaw: ByteArray, bckIdRaw: ByteArray): ByteArray {
    val backupKey = BackupKey(bckKeyRaw)
    val msgBackupKey = MessageBackupKey(backupKey, bckIdRaw)

    return msgBackupKey.serialize()
  }

  internal fun messageBackupKeyGetHmacKey(msgBckKey: ByteArray): ByteArray {
    val messageBackupKey = deserializeMessageBackupKey(msgBckKey)

    return messageBackupKey.hmacKey
  }

  internal fun messageBackupKeyGetAesKey(msgBckKey: ByteArray): ByteArray {
    val messageBackupKey = deserializeMessageBackupKey(msgBckKey)

    return messageBackupKey.aesKey
  }

  internal fun messageBackupValidatorValidate(msgBckKey: ByteArray, path: String, len: Long, purpose: Int): List<String> {
    val messageBackupKey = deserializeMessageBackupKey(msgBckKey)

    val fac: () -> InputStream = {
      val file = File(path.replace("file:/", "")  );
      FileInputStream(file)
    }

    val result = MessageBackup.validate(messageBackupKey, purposeFromInt(purpose), fac, len)

    return result.unknownFieldMessages.toList()
  }

  internal fun onlineBackupValidatorNew(bckInfo: ByteArray, purpose: Int): String {
    val obckval = OnlineBackupValidator(bckInfo, purposeFromInt(purpose))

    val shortId = generateShortId()
    this.handles[shortId] = obckval

    return shortId
  }

  internal fun onlineBackupValidatorAddFrame(handle: String, frame: ByteArray) {
    val onlineBackupValidator = this.handles[handle] as OnlineBackupValidator

    onlineBackupValidator.addFrame(frame)
  }

  internal fun onlineBackupValidatorFinalize(handle: String) {
    val onlineBackupValidator = this.handles[handle] as OnlineBackupValidator

    onlineBackupValidator.close()

    this.handles.remove(handle)
  }

  internal fun comparableBackupReadUnencrypted(filePath: String, len: Long, purpose: Int): String {
    val file = File(filePath.replace("file:/", ""));
    val inp = FileInputStream(file)

    val cmpBck = ComparableBackup.readUnencrypted(purposeFromInt(purpose), inp, len)

    val shortId = generateShortId()
    this.handles[shortId] = cmpBck

    return shortId
  }

  internal fun comparableBackupGetInfo(handle: String): List<Any> {
    val cmpBck = this.handles[handle] as ComparableBackup
    this.handles.remove(handle)

    return listOf(cmpBck.comparableString, cmpBck.unknownFieldMessages.toList())
  }
}

fun parseCiphertext(msg: ByteArray, msgType: Int): CiphertextMessage {
    return when (msgType) {
        2 -> SignalMessage(msg)
        3 -> PreKeySignalMessage(msg)
        7 -> SenderKeyMessage(msg)
        8 -> PlaintextContent(msg)
        else -> throw Error("invalid ciphertext type")
    }
}

fun parseUuidCipherTexts(raw: ByteArray): MutableList<UuidCiphertext> {
    if (raw.size % 65 != 0) {
        throw Error("invalid uuid ciphertexts length")
    }

    val clc: MutableList<UuidCiphertext> = mutableListOf()
    val count = raw.size / 65
    for (i in 1..count) {
        val cphtx = UuidCiphertext(raw.slice((i-1)*65..(i*65)-1).toByteArray())
        clc.add(cphtx)
    }

    return clc
}

fun parseFixedWidthServiceIds(raw: ByteArray): MutableList<ServiceId> {
    if (raw.size % 17 != 0) {
        throw Error("invalid service ids length")
    }

    val clc: MutableList<ServiceId> = mutableListOf()
    val count = raw.size / 17
    for (i in 1..count) {
        val svcid = ServiceId.parseFromFixedWidthBinary(raw.slice((i-1)*17..(i*17)-1).toByteArray())
        clc.add(svcid)
    }

    return clc
}

fun BackupCredentialType.toNumber(): Int {
    return when (this) {
        BackupCredentialType.MEDIA -> 2
        BackupCredentialType.MESSAGES -> 1
    }
}

fun BackupLevel.toNumber(): Int {
    return when (this) {
        BackupLevel.PAID -> 201
        BackupLevel.FREE -> 200
    }
}

fun MessageBackupKey.serialize(): ByteArray {
  return this.hmacKey+this.aesKey
}

fun purposeFromInt(purpose: Int): Purpose {
  return when (purpose) {
    0 -> Purpose.DEVICE_TRANSFER
    1 -> Purpose.REMOTE_BACKUP
    else -> throw Error("invalid purpose")
  }
}

fun deserializeMessageBackupKey(ser: ByteArray): MessageBackupKey {
  if (ser.size != 64) {
    throw Error("invalid message backup key")
  }

  val hmac = ser.slice(0..31).toByteArray()
  val aes = ser.slice(32..63).toByteArray()

  return MessageBackupKey.fromParts(hmac, aes)
}

fun generateShortId(length: Int = 8): String {
  val charPool = ('a'..'z') + ('A'..'Z') + ('0'..'9')
  return (1..length)
    .map { charPool.random() }
    .joinToString("")
}

fun initiateCipherFromType(type: String, key: ByteArray, iv: ByteArray, mode: String): Cipher {
  val cipherMode = when (mode) {
    "encrypt" -> {
      Cipher.ENCRYPT_MODE
    }
    "decrypt" -> {
      Cipher.DECRYPT_MODE
    }
    else -> {
      throw Error("invalid cipher mode:" + mode)
    }
  }
  when (type) {
    "AES/GCM/NoPadding" -> {
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      val gcmSpec = GCMParameterSpec(128, iv)
      cipher.init(
        cipherMode,
        SecretKeySpec(key, "AES"),
        gcmSpec
      )

      return cipher
    }
    "AES/CBC/PKCS5Padding" -> {
      val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      cipher.init(
        cipherMode,
        SecretKeySpec(key, "AES"),
        IvParameterSpec(iv)
      )

      return cipher
    }
    else -> throw Error("invalid cipher type "+type)
  }
}