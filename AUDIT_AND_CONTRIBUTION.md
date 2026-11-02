# Audit Notes & Contribution Guide

This directory (`C:\chat\libsignal-client`) is a standalone copy of `react-native-libsignal-client` incorporating all critical Android compiler, runtime serialization, and configuration fixes.

## Key Changes Included
1. **Kotlin OOM Modularization:** Decomposed monolithic `ReactNativeLibsignalClientModule.kt` into domain Kotlin files (`BackupFunctions.kt`, `CryptoPrimitivesFunctions.kt`, `GroupAndSenderKeyFunctions.kt`, `IdentityAndKeyFunctions.kt`, `SessionAndRatchetFunctions.kt`, `ZkGroupFunctions.kt`, `ElasticCipher.kt`).
2. **Bridge Serialization Fix:** Replaced Kotlin `Pair<...>` with `List<...>` / `listOf(...)` to ensure Expo Modules Core serializes native tuples to JS without runtime crashes.
3. **Circular Import Resolution:** Fixed self-imports in `Errors.ts` and `index.ts`.
4. **Peer Dependency Best Practice:** Shifted `expo-build-properties` from dependencies to peerDependencies.

## Upstream Target
* Repo: `https://github.com/ehsunahmadi/react-native-libsignal-client`
* Ready to initialize as git repo and submit PR.

