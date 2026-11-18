import ExpoModulesCore
import CommonCrypto
import CryptoKit
import UIKit

/**
 * Native PBKDF2-SHA256 via Apple's CommonCrypto (CCKeyDerivationPBKDF).
 * The web app gets native-speed PBKDF2 through SubtleCrypto; this gives the
 * native app the same — the pure-JS path costs ~2 MINUTES per unlock attempt
 * on-device (210k iterations of JS HMAC vs milliseconds here).
 * Byte-identical output to the JS/Node path (asserted in the device test suite).
 */
public class VeilCryptoModule: Module {
  // NOTE (b48 fix): do NOT wrap this in an explicit `ModuleDefinition { ... }`
  // call — in this ExpoModulesCore version ModuleDefinition's initializer is
  // internal and doesn't accept a trailing closure. The function body IS the
  // result-builder DSL; Name(...)/AsyncFunction(...) go directly here.
  public func definition() -> ModuleDefinition {
    Name("VeilCrypto")

    // ---------- Screenshot / screen-recording watch (b61) ----------
    // iOS gives no way to BLOCK the hardware screenshot, but it fires
    // UIApplication.userDidTakeScreenshotNotification the moment one is
    // taken, and UIScreen.capturedDidChangeNotification for AirPlay /
    // screen recording. The JS side turns these into an in-thread
    // notice to the other party (Snapchat-style, post-hoc deterrent).
    Events("onScreenCapture", "onProtectedData") // b77t (audit 5): + the iOS lock signal below
    // (b64) BUG FIX: the block-based addObserver returns an observer token
    // that MUST be retained — the previous code discarded it, so the token
    // deallocated immediately and iOS stopped delivering the notifications
    // entirely. On-device symptom: screenshots happened with no notice, no
    // local amber line, nothing ("no deterrent"). Tokens are now held in a
    // static on the module class and removed in OnDestroy.
    OnCreate {
      let shot = NotificationCenter.default.addObserver(
        forName: UIApplication.userDidTakeScreenshotNotification,
        object: nil,
        queue: .main
      ) { [weak self] _ in
        self?.sendEvent("onScreenCapture", ["kind": "screenshot"])
      }
      let rec = NotificationCenter.default.addObserver(
        forName: UIScreen.capturedDidChangeNotification,
        object: nil,
        queue: .main
      ) { [weak self] note in
        if let screen = note.object as? UIScreen {
          self?.sendEvent("onScreenCapture", ["kind": "recording", "captured": screen.isCaptured])
        }
      }
      // b77t (audit 5, owner decision "iOS screen lock: fix pre-emptively"): the phone is locking (data
      // protection is about to drop its keys). JS locks Vardum at once (src/protected-data.ts); iOS may
      // report a screen lock to the app as 'inactive' only, never 'background'.
      let pdu = NotificationCenter.default.addObserver(
        forName: UIApplication.protectedDataWillBecomeUnavailableNotification,
        object: nil,
        queue: .main
      ) { [weak self] _ in
        self?.sendEvent("onProtectedData", ["available": false])
      }
      VeilCryptoModule.captureObservers = [shot, rec, pdu]
    }
    OnDestroy {
      VeilCryptoModule.captureObservers.forEach { NotificationCenter.default.removeObserver($0) }
      VeilCryptoModule.captureObservers = []
    }

    // ---------- Secure Enclave hardware seal (b62) ----------
    // "Hardware" key storage: the identity keyvault master key is sealed with
    // an AES-GCM key derived from an ECDH agreement with a P-256 private key
    // that lives ONLY in the Secure Enclave (non-extractable, biometry-gated).
    // The wrapped blob in the keychain is useless off-device; unwrapping
    // demands Face ID / Touch ID at the Secure Enclave key-use itself.
    Function("seIsAvailable") { () -> Bool in
      SecureEnclave.isAvailable
    }

    AsyncFunction("seWrapKey") { (masterKeyB64: String) -> [String: String] in
      let seKey = try VeilCryptoModule.loadOrCreateSeKey()
      let master = Data(base64Encoded: masterKeyB64)
      if master == nil || master!.isEmpty {
        throw NSError(domain: "VeilCrypto", code: 40, userInfo: [NSLocalizedDescriptionKey: "seWrapKey: master key is not valid base64"])
      }
      let eph = try P256.KeyAgreement.PrivateKey()
      let shared = try eph.sharedSecretFromKeyAgreement(with: seKey.publicKey)
      var salt = Data(count: 32)
      // D-19 (RV-16): a failed CSPRNG call must not leave an all-zero salt.
      let rng = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
      if rng != errSecSuccess {
        throw NSError(domain: "VeilCrypto", code: 45, userInfo: [NSLocalizedDescriptionKey: "seWrapKey: SecRandomCopyBytes failed (\(rng))"])
      }
      let sym = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data("veil-se-wrap-v1".utf8), outputByteCount: 32)
      let sealed = try AES.GCM.seal(master!, using: sym)
      guard let combined = sealed.combined else {
        throw NSError(domain: "VeilCrypto", code: 41, userInfo: [NSLocalizedDescriptionKey: "seWrapKey: seal failed"])
      }
      return [
        "eph": eph.publicKey.x963Representation.base64EncodedString(),
        "salt": salt.base64EncodedString(),
        "ct": combined.base64EncodedString(),
      ]
    }

    AsyncFunction("seUnwrapKey") { (ephB64: String, saltB64: String, ctB64: String) -> String in
      // (try? on an Optional-returning call flattens in Swift 5: nil = no key or error)
      guard let seKey = try? VeilCryptoModule.loadSeKey() else {
        throw NSError(domain: "VeilCrypto", code: 42, userInfo: [NSLocalizedDescriptionKey: "seUnwrapKey: Secure Enclave key unavailable (re-enrolled biometrics?)"])
      }
      guard let ephData = Data(base64Encoded: ephB64),
            let salt = Data(base64Encoded: saltB64),
            let ct = Data(base64Encoded: ctB64),
            let ephPub = try? P256.KeyAgreement.PublicKey(x963Representation: ephData) else {
        throw NSError(domain: "VeilCrypto", code: 43, userInfo: [NSLocalizedDescriptionKey: "seUnwrapKey: malformed sealed blob"])
      }
      let shared = try seKey.sharedSecretFromKeyAgreement(with: ephPub) // biometric prompt here
      let sym = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data("veil-se-wrap-v1".utf8), outputByteCount: 32)
      let box = try AES.GCM.SealedBox(combined: ct)
      let plain = try AES.GCM.open(box, using: sym)
      return plain.base64EncodedString()
    }

    // b102: delete the persisted SE key and recreate it with the CURRENT
    // biometry-gated access control. Devices that first touched hardware mode
    // before b100 carry an SE key created by the old seAccessControl flags
    // (no biometry constraint) — loadOrCreateSeKey() happily reuses it
    // forever, so unwrap never prompts Face ID (owner hardware finding,
    // surviving b96-b101: "none of the modes ask me for biometrics"). Only
    // safe to call when the keyvault identity is in memory and is about to be
    // re-sealed: the old sealed blob becomes unreadable the moment this runs.
    // D-19 (RV-16): the delete used to ignore its status (and passed a query
    // carrying kSecReturnData), so a failed delete silently kept the old,
    // ungated key and still returned true. Now: delete with a plain match
    // query, accept only success / not-found, confirm the item is gone, and
    // always CREATE a fresh key (never reuse whatever is there).
    AsyncFunction("seResetKey") { () -> Bool in
      let del = SecItemDelete(VeilCryptoModule.seMatchQuery() as CFDictionary)
      if del != errSecSuccess && del != errSecItemNotFound {
        throw NSError(domain: "VeilCrypto", code: 46, userInfo: [NSLocalizedDescriptionKey: "seResetKey: SecItemDelete failed (\(del))"])
      }
      if try VeilCryptoModule.loadSeKey() != nil {
        throw NSError(domain: "VeilCrypto", code: 46, userInfo: [NSLocalizedDescriptionKey: "seResetKey: old Secure Enclave key still present after delete"])
      }
      _ = try VeilCryptoModule.createSeKey()
      return true
    }

    // ---------- App-lock MAC (b70 audit fix VAR-07) ----------
    // The app-lock verifier is HMAC(key, PBKDF2(code)) where the key comes
    // from an ECDH agreement between a Secure Enclave P-256 key (no biometry:
    // the lock screen must work without Face ID) and a stored peer public key
    // whose private half was thrown away at creation. Nobody can compute the
    // agreement without this phone's Secure Enclave, so a copied lock record
    // can't be guessed offline.
    Function("lockMacAvailable") { () -> Bool in
      SecureEnclave.isAvailable
    }

    // b75 (audit AL-11): the lock key is a Secure Enclave key whenever lockMacAvailable
    // is true (iOS has no software fallback for it), so the two answers agree here.
    Function("lockMacHardware") { () -> Bool in
      SecureEnclave.isAvailable
    }

    AsyncFunction("lockMac") { (inputHex: String) -> String in
      let input = VeilCryptoModule.hexToBytes(inputHex)
      if input.isEmpty {
        throw NSError(domain: "VeilCrypto", code: 60, userInfo: [NSLocalizedDescriptionKey: "lockMac: input is not valid hex"])
      }
      let seKey = try VeilCryptoModule.loadOrCreateLockKey()
      let peer = try VeilCryptoModule.loadOrCreateLockPeer()
      let shared = try seKey.sharedSecretFromKeyAgreement(with: peer)
      let key = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data("vardum-lock-mac-v1".utf8), outputByteCount: 32)
      let mac = HMAC<SHA256>.authenticationCode(for: Data(input), using: key)
      return VeilCryptoModule.bytesToHex(Array(mac))
    }

    AsyncFunction("lockMacReset") { () -> Bool in
      for q in [VeilCryptoModule.lockKeyQuery(), VeilCryptoModule.lockPeerQuery()] {
        let del = SecItemDelete(q as CFDictionary)
        if del != errSecSuccess && del != errSecItemNotFound {
          throw NSError(domain: "VeilCrypto", code: 61, userInfo: [NSLocalizedDescriptionKey: "lockMacReset: SecItemDelete failed (\(del))"])
        }
      }
      return true
    }

    // b71 (audit): copy text that stays on this phone (never Universal Clipboard to
    // the user's other Apple devices) and expires by itself after expireSeconds.
    AsyncFunction("setSensitiveClipboard") { (text: String, expireSeconds: Double) -> Bool in
      let item: [String: Any] = ["public.utf8-plain-text": text]
      UIPasteboard.general.setItems([item], options: [
        UIPasteboard.OptionsKey.localOnly: true,
        UIPasteboard.OptionsKey.expirationDate: Date().addingTimeInterval(max(1, expireSeconds)),
      ])
      return true
    }.runOnQueue(.main)

    // b70 (audit L-5): keep a saved file out of iCloud / iTunes backups.
    // b77s (audit 4 A-01): every wipe drops the app's cookies (React Native's networking uses the shared
    // HTTPCookieStorage), so a relay that set one can't link requests made before and after a wipe.
    // (Not compiled in the b77s round: no Xcode there; needs a device build check.)
    AsyncFunction("clearCookies") { () -> Bool in
      let store = HTTPCookieStorage.shared
      for cookie in store.cookies ?? [] { store.deleteCookie(cookie) }
      return true
    }

    AsyncFunction("excludeFromBackup") { (path: String) -> Bool in
      guard var url = URL(string: path), url.isFileURL else { return false }
      var values = URLResourceValues()
      values.isExcludedFromBackup = true
      try url.setResourceValues(values)
      return true
    }

    // ---------- b75 (audit AL-10): delete the Secure Enclave wrap key outright ----------
    // seResetKey always makes a fresh key, so a wiped phone still held one. This
    // deletes it and makes none (the next hardware-mode seal creates a new one).
    AsyncFunction("seDeleteKey") { () -> Bool in
      let del = SecItemDelete(VeilCryptoModule.seMatchQuery() as CFDictionary)
      if del != errSecSuccess && del != errSecItemNotFound {
        throw NSError(domain: "VeilCrypto", code: 46, userInfo: [NSLocalizedDescriptionKey: "seDeleteKey: SecItemDelete failed (\(del))"])
      }
      return try VeilCryptoModule.loadSeKey() == nil
    }

    // ---------- b75 (audit AL-6): container keys ----------
    // Every secure-store value is AES-GCM sealed (in JS) under a random 256-bit key
    // kept in a file in this app's Application Support directory, excluded from
    // backups, with file protection "until first unlock" (background receive reads
    // the login while the phone is locked). Keychain items survive deleting the app;
    // this file does not, so whatever the Keychain keeps after a delete is useless.
    // Deleting the file is the crypto-shred every wipe does first.
    // File: [ver=1][gen:4 BE][key:32].
    // an empty dictionary = no file in this slot (JS reads it as null)
    AsyncFunction("ckRead") { (slot: String) -> [String: Any] in
      let url = try VeilCryptoModule.ckFile(slot)
      if !FileManager.default.fileExists(atPath: url.path) { return [:] }
      let data = try Data(contentsOf: url) // a read error throws: never "absent"
      let b = [UInt8](data)
      if b.count != 1 + 4 + 32 || b[0] != 1 {
        throw NSError(domain: "VeilCrypto", code: 80, userInfo: [NSLocalizedDescriptionKey: "container key file is malformed"])
      }
      let gen = Int(UInt32(b[1]) << 24 | UInt32(b[2]) << 16 | UInt32(b[3]) << 8 | UInt32(b[4]))
      return ["key": Data(b[5..<37]).base64EncodedString(), "gen": gen]
    }

    AsyncFunction("ckCreate") { (slot: String, gen: Int) -> [String: Any] in
      let url = try VeilCryptoModule.ckFile(slot)
      // never overwrite: a key in use is only ever replaced by remove + create
      if FileManager.default.fileExists(atPath: url.path) {
        throw NSError(domain: "VeilCrypto", code: 81, userInfo: [NSLocalizedDescriptionKey: "container key slot is in use"])
      }
      var key = [UInt8](repeating: 0, count: 32)
      let rng = SecRandomCopyBytes(kSecRandomDefault, 32, &key)
      if rng != errSecSuccess {
        throw NSError(domain: "VeilCrypto", code: 82, userInfo: [NSLocalizedDescriptionKey: "SecRandomCopyBytes failed (\(rng))"])
      }
      defer { VeilCryptoModule.wipe(&key) }
      let g = UInt32(truncatingIfNeeded: gen)
      var out: [UInt8] = [1, UInt8(g >> 24 & 0xff), UInt8(g >> 16 & 0xff), UInt8(g >> 8 & 0xff), UInt8(g & 0xff)]
      out.append(contentsOf: key)
      defer { VeilCryptoModule.wipe(&out) }
      try VeilCryptoModule.ckWriteDurably(Data(out), to: url)
      return ["key": Data(key).base64EncodedString(), "gen": gen]
    }

    AsyncFunction("ckRemove") { (slot: String) -> Bool in
      let url = try VeilCryptoModule.ckFile(slot)
      try VeilCryptoModule.ckShred(url)
      return !FileManager.default.fileExists(atPath: url.path)
    }

    AsyncFunction("ckRemoveAll") { () -> Bool in
      let dir = try VeilCryptoModule.ckDir()
      for f in (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? [] {
        try VeilCryptoModule.ckShred(f)
      }
      return true
    }

    // b75 (audit DEV-I6): the key file is protected only by iOS file protection, readable by
    // this app after the first unlock; no Secure Enclave or Keychain key wraps it. It used to
    // answer a constant hardware: true.
    Function("ckInfo") { () -> [String: Bool] in
      ["hardware": false, "unlockBound": false]
    }

    // Time since boot, counting sleep (Darwin CLOCK_MONOTONIC). Changing the
    // phone's clock doesn't move it, so lockouts can't be skipped that way.
    Function("uptimeMs") { () -> Double in
      Double(clock_gettime_nsec_np(CLOCK_MONOTONIC)) / 1_000_000.0
    }

    AsyncFunction("pbkdf2Sha256") { (password: String, saltHex: String, iterations: Int, dkLen: Int) -> String in
        let salt = VeilCryptoModule.hexToBytes(saltHex)
        if salt.isEmpty {
          throw NSError(domain: "VeilCrypto", code: 1, userInfo: [NSLocalizedDescriptionKey: "invalid salt hex"])
        }
        // RV-27: same bounds as the JS entry point (vendor/device/src/kdf.ts
        // pbkdf2Sha256Bytes). Also keeps UInt32(iterations) and the dkLen
        // allocation below from trapping on out-of-range input.
        if iterations < VeilCryptoModule.pbkdf2MinIterations || iterations > VeilCryptoModule.pbkdf2MaxIterations
            || dkLen < 16 || dkLen > 64 {
          throw NSError(domain: "VeilCrypto", code: 3, userInfo: [NSLocalizedDescriptionKey: "pbkdf2Sha256: unsupported iterations or dkLen"])
        }
        // RV-28: hash the raw UTF-8 bytes, like JS and Android. cString(using:)
        // could stop at an embedded NUL. The 1-byte pad only gives an empty
        // password a valid pointer; the length passed is the real one.
        var pw = Array(password.utf8)
        let pwLen = pw.count
        if pw.isEmpty { pw = [0] }
        var derived = [UInt8](repeating: 0, count: dkLen)
        // RV-29: clear the password copy and the derived bytes once done.
        defer {
          VeilCryptoModule.wipe(&pw)
          VeilCryptoModule.wipe(&derived)
        }
        let status: Int32 = pw.withUnsafeBufferPointer { pwBuf -> Int32 in
          salt.withUnsafeBufferPointer { saltBuf -> Int32 in
            derived.withUnsafeMutableBufferPointer { dBuf -> Int32 in
              CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                pwBuf.baseAddress, pwLen,
                saltBuf.baseAddress, salt.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                UInt32(iterations),
                dBuf.baseAddress, dkLen)
            }
          }
        }
        if status != kCCSuccess {
          throw NSError(domain: "VeilCrypto", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "CCKeyDerivationPBKDF failed (\(status))"])
        }
        return VeilCryptoModule.bytesToHex(derived)
    }

    // ---------- AES-256-GCM (CryptoKit) ----------
    // Added b54: the pure-JS noble AES-GCM shim costs ~30s+ on Hermes for the
    // multi-MB vault/stego/transfer payloads. CryptoKit's sealed-box layout is
    // ciphertext||tag — byte-identical to noble's combined output, so the JS
    // side can fall in/out without any format change.

    AsyncFunction("aesGcmEncrypt") { (keyHex: String, ivHex: String, plaintextBase64: String, aadHex: String) -> String in
        let keyBytes = VeilCryptoModule.hexToBytes(keyHex)
        if keyBytes.count != 32 {
          throw NSError(domain: "VeilCrypto", code: 10, userInfo: [NSLocalizedDescriptionKey: "aesGcmEncrypt: key must be 32 bytes"])
        }
        let iv = VeilCryptoModule.hexToBytes(ivHex)
        if iv.count != 12 {
          throw NSError(domain: "VeilCrypto", code: 11, userInfo: [NSLocalizedDescriptionKey: "aesGcmEncrypt: iv must be 12 bytes"])
        }
        guard let pt = Data(base64Encoded: plaintextBase64) else {
          throw NSError(domain: "VeilCrypto", code: 12, userInfo: [NSLocalizedDescriptionKey: "aesGcmEncrypt: invalid base64 plaintext"])
        }
        let aad = Data(try VeilCryptoModule.strictHexToBytes(aadHex)) // b77t (audit 5 L-31): malformed AAD hex is refused, never read as no AAD
        let key = SymmetricKey(data: Data(keyBytes))
        let nonce = try AES.GCM.Nonce(data: Data(iv))
        let sealed = try AES.GCM.seal(pt, using: key, nonce: nonce, authenticating: aad)
        // combined = ciphertext || tag(16) — same layout noble produces
        return (sealed.ciphertext + sealed.tag).base64EncodedString()
    }

    AsyncFunction("aesGcmDecrypt") { (keyHex: String, ivHex: String, combinedBase64: String, aadHex: String) -> String in
        let keyBytes = VeilCryptoModule.hexToBytes(keyHex)
        if keyBytes.count != 32 {
          throw NSError(domain: "VeilCrypto", code: 13, userInfo: [NSLocalizedDescriptionKey: "aesGcmDecrypt: key must be 32 bytes"])
        }
        let iv = VeilCryptoModule.hexToBytes(ivHex)
        if iv.count != 12 {
          throw NSError(domain: "VeilCrypto", code: 14, userInfo: [NSLocalizedDescriptionKey: "aesGcmDecrypt: iv must be 12 bytes"])
        }
        guard let combined = Data(base64Encoded: combinedBase64) else {
          throw NSError(domain: "VeilCrypto", code: 15, userInfo: [NSLocalizedDescriptionKey: "aesGcmDecrypt: invalid base64 ciphertext"])
        }
        if combined.count < 16 {
          throw NSError(domain: "VeilCrypto", code: 16, userInfo: [NSLocalizedDescriptionKey: "aesGcmDecrypt: ciphertext shorter than a bare GCM tag"])
        }
        let aad = Data(try VeilCryptoModule.strictHexToBytes(aadHex)) // b77t (audit 5 L-31): malformed AAD hex is refused, never read as no AAD
        let key = SymmetricKey(data: Data(keyBytes))
        let nonce = try AES.GCM.Nonce(data: Data(iv))
        let ct = combined.prefix(combined.count - 16)
        let tag = combined.suffix(16)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
        // GCM tag mismatch (wrong key/passphrase) gets a DISTINCT error code so
        // the JS side can tell "bad passphrase" (must propagate immediately —
        // the JS fallback would burn ~30s reaching the same conclusion) apart
        // from "bridge/module problem" (safe to retry in JS).
        // CryptoKitError is an enum (no isAuthenticationFailure property) —
        // match the .authenticationFailure case directly. (b55 fix: the
        // property-based check doesn't exist on this SDK's CryptoKitError.)
        let pt: Data
        do {
          pt = try AES.GCM.open(box, using: key, authenticating: aad)
        } catch CryptoKitError.authenticationFailure {
          throw NSError(domain: "VeilCrypto", code: 20, userInfo: [NSLocalizedDescriptionKey: "authentication failure (GCM tag mismatch)"])
        }
        return pt.base64EncodedString()
    }

    // ---------- randomBytes (SecRandomCopyBytes) ----------
    // Added b57: the 24 MB vault container fill used to be 384 separate JS
    // bridge calls to react-native-get-random-values (several seconds on
    // device). One native call fills the whole buffer instead.
    AsyncFunction("randomBytesBase64") { (byteLength: Int) -> String in
        if byteLength <= 0 || byteLength > 64 * 1024 * 1024 {
          throw NSError(domain: "VeilCrypto", code: 30, userInfo: [NSLocalizedDescriptionKey: "randomBytesBase64: length out of range"])
        }
        var bytes = [UInt8](repeating: 0, count: byteLength)
        let status = SecRandomCopyBytes(kSecRandomDefault, byteLength, &bytes)
        if status != errSecSuccess {
          throw NSError(domain: "VeilCrypto", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "SecRandomCopyBytes failed (\(status))"])
        }
        return Data(bytes).base64EncodedString()
    }
  }

  // ---------- Secure Enclave key persistence ----------
  // (b64) retained NotificationCenter tokens for the capture watch — see OnCreate
  private static var captureObservers: [NSObjectProtocol] = []
  private static let seKeyService = "au.com.mattthemagicalmentalist.veil.se-key"
  private static let seKeyAccount = "veil-se"

  // D-19 (RV-16): every step of the SE key lifecycle now fails closed.
  // Before, a nil access control silently created a key with NO biometric
  // gate, and the SecItemAdd / SecItemDelete / SecItemCopyMatching statuses
  // were ignored (a key could be used to seal without ever being stored, and
  // seResetKey could silently keep the old key).
  private static func seAccessControl() throws -> SecAccessControl {
    var err: Unmanaged<CFError>?
    guard let acl = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      [.privateKeyUsage, .biometryCurrentSet],
      &err
    ) else {
      let why = err.map { String(describing: $0.takeRetainedValue()) } ?? "unknown"
      throw NSError(domain: "VeilCrypto", code: 47, userInfo: [NSLocalizedDescriptionKey: "Secure Enclave access control could not be created (\(why)); refusing to create an ungated key"])
    }
    return acl
  }

  /// Match-only query (no return-type keys): safe for SecItemDelete.
  private static func seMatchQuery() -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: seKeyService,
      kSecAttrAccount as String: seKeyAccount,
    ]
  }

  /// Load the stored SE key representation (the raw blob itself is useless
  /// outside this device's Secure Enclave — that is the point).
  /// Returns nil ONLY when no item exists (errSecItemNotFound). Any other
  /// keychain status (e.g. errSecInteractionNotAllowed while locked) or an
  /// unreadable stored blob throws, so callers never mistake "can't read it
  /// right now" for "there is none" and mint a replacement key.
  private static func loadSeKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey? {
    var q = seMatchQuery()
    q[kSecReturnData as String] = true
    q[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    let status = SecItemCopyMatching(q as CFDictionary, &item)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess else {
      throw NSError(domain: "VeilCrypto", code: 44, userInfo: [NSLocalizedDescriptionKey: "SE key lookup failed (\(status))"])
    }
    guard let data = item as? Data,
          let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data) else {
      throw NSError(domain: "VeilCrypto", code: 44, userInfo: [NSLocalizedDescriptionKey: "stored SE key is unreadable (reset needed)"])
    }
    return key
  }

  /// Create a new biometry-gated SE key and persist it. Throws if the access
  /// control can't be built or the keychain write fails — a key that was not
  /// stored is never returned (anything sealed to it would be lost).
  private static func createSeKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
    let acl = try seAccessControl()
    let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: acl)
    var add = seMatchQuery()
    add[kSecValueData as String] = key.dataRepresentation
    // Explicit class (RV-57): the item holds only an SE handle, useless on
    // another device, so it must never travel in a backup or restore.
    add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else {
      throw NSError(domain: "VeilCrypto", code: 48, userInfo: [NSLocalizedDescriptionKey: "SE key could not be stored (SecItemAdd \(status))"])
    }
    return key
  }

  /// Load the existing SE key or create + persist a new biometry-gated one.
  private static func loadOrCreateSeKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
    if let existing = try loadSeKey() { return existing }
    return try createSeKey()
  }

  // ---------- App-lock key (VAR-07) ----------
  private static let lockKeyService = "au.com.mattthemagicalmentalist.veil.lock-key"
  private static let lockPeerService = "au.com.mattthemagicalmentalist.veil.lock-peer"

  private static func lockKeyQuery() -> [String: Any] {
    [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: lockKeyService, kSecAttrAccount as String: "veil-lock"]
  }

  private static func lockPeerQuery() -> [String: Any] {
    [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: lockPeerService, kSecAttrAccount as String: "veil-lock"]
  }

  /// Read one generic-password item. nil only when it doesn't exist; any other
  /// status throws, so "can't read it now" never becomes "make a new one".
  private static func readItem(_ query: [String: Any]) throws -> Data? {
    var q = query
    q[kSecReturnData as String] = true
    q[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    let status = SecItemCopyMatching(q as CFDictionary, &item)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess, let data = item as? Data else {
      throw NSError(domain: "VeilCrypto", code: 62, userInfo: [NSLocalizedDescriptionKey: "lock key lookup failed (\(status))"])
    }
    return data
  }

  private static func addItem(_ query: [String: Any], _ data: Data) throws {
    var add = query
    add[kSecValueData as String] = data
    add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else {
      throw NSError(domain: "VeilCrypto", code: 63, userInfo: [NSLocalizedDescriptionKey: "lock key could not be stored (SecItemAdd \(status))"])
    }
  }

  private static func loadOrCreateLockKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
    if let data = try readItem(lockKeyQuery()) {
      guard let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data) else {
        throw NSError(domain: "VeilCrypto", code: 64, userInfo: [NSLocalizedDescriptionKey: "stored lock key is unreadable"])
      }
      return key
    }
    var err: Unmanaged<CFError>?
    guard let acl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &err) else {
      throw NSError(domain: "VeilCrypto", code: 65, userInfo: [NSLocalizedDescriptionKey: "lock key access control could not be created"])
    }
    let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: acl)
    try addItem(lockKeyQuery(), key.dataRepresentation)
    return key
  }

  private static func loadOrCreateLockPeer() throws -> P256.KeyAgreement.PublicKey {
    if let data = try readItem(lockPeerQuery()) {
      guard let pub = try? P256.KeyAgreement.PublicKey(x963Representation: data) else {
        throw NSError(domain: "VeilCrypto", code: 64, userInfo: [NSLocalizedDescriptionKey: "stored lock peer key is unreadable"])
      }
      return pub
    }
    // the private half goes out of scope here and is never stored
    let pub = P256.KeyAgreement.PrivateKey().publicKey
    try addItem(lockPeerQuery(), pub.x963Representation)
    return pub
  }

  // ---------- b75 (AL-6) container key files ----------
  private static func ckDir() throws -> URL {
    let base = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
    var dir = base.appendingPathComponent("vardum-ck", isDirectory: true)
    if !FileManager.default.fileExists(atPath: dir.path) {
      try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
        attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
    }
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    try dir.setResourceValues(values)
    return dir
  }

  private static func ckFile(_ slot: String) throws -> URL {
    guard slot.count == 1, let c = slot.unicodeScalars.first, c.value >= 0x61 && c.value <= 0x7a else {
      throw NSError(domain: "VeilCrypto", code: 83, userInfo: [NSLocalizedDescriptionKey: "bad container key slot"])
    }
    return try ckDir().appendingPathComponent("\(slot).ck")
  }

  /// temp file, F_FULLFSYNC, rename, then the directory: durable before the key is used
  private static func ckWriteDurably(_ data: Data, to url: URL) throws {
    let tmp = url.deletingLastPathComponent().appendingPathComponent(url.lastPathComponent + ".tmp")
    _ = FileManager.default.createFile(atPath: tmp.path, contents: nil,
      attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
    let fh = try FileHandle(forWritingTo: tmp)
    do {
      try fh.write(contentsOf: data)
      _ = fcntl(fh.fileDescriptor, F_FULLFSYNC)
      try fh.close()
    } catch {
      try? fh.close()
      try? FileManager.default.removeItem(at: tmp)
      throw error
    }
    if rename(tmp.path, url.path) != 0 {
      try? FileManager.default.removeItem(at: tmp)
      throw NSError(domain: "VeilCrypto", code: 84, userInfo: [NSLocalizedDescriptionKey: "container key file could not be placed"])
    }
    var u = url
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    try? u.setResourceValues(values)
    let dfd = open(url.deletingLastPathComponent().path, O_RDONLY)
    if dfd >= 0 { _ = fcntl(dfd, F_FULLFSYNC); close(dfd) }
  }

  /// overwrite with zeros, sync, delete. b75 round 2 (audit I2): the delete (the key is gone)
  /// is the protection; the zero overwrite is best-effort (flash storage may keep old blocks).
  private static func ckShred(_ url: URL) throws {
    if !FileManager.default.fileExists(atPath: url.path) { return }
    if let fh = try? FileHandle(forUpdating: url) {
      let n = (try? fh.seekToEnd()) ?? 0
      try? fh.seek(toOffset: 0)
      try? fh.write(contentsOf: Data(count: Int(n)))
      _ = fcntl(fh.fileDescriptor, F_FULLFSYNC)
      try? fh.close()
    }
    try FileManager.default.removeItem(at: url)
  }

  /// Must match PBKDF2_MIN_ITERATIONS / PBKDF2_MAX_ITERATIONS in vendor/device/src/kdf.ts.
  private static let pbkdf2MinIterations = 100_000
  private static let pbkdf2MaxIterations = 1_000_000

  /// Zero a byte buffer in place (memset_s is never optimised away).
  private static func wipe(_ bytes: inout [UInt8]) {
    let n = bytes.count
    bytes.withUnsafeMutableBytes { buf in
      if let p = buf.baseAddress { _ = memset_s(p, n, 0, n) }
    }
  }

  /// b77t (audit 5 L-31, IH DEV-8): hex that must be well-formed (the AES-GCM AAD). hexToBytes returns [] for
  /// malformed hex, which for the AAD meant "no AAD" (fail open); this throws instead. "" = no AAD.
  private static func strictHexToBytes(_ hex: String) throws -> [UInt8] {
    let out = VeilCryptoModule.hexToBytes(hex)
    if out.count * 2 != hex.utf8.count {
      throw NSError(domain: "VeilCrypto", code: 17, userInfo: [NSLocalizedDescriptionKey: "malformed hex (AAD)"])
    }
    return out
  }

  private static func hexToBytes(_ hex: String) -> [UInt8] {
    let chars = Array(hex.utf8)
    if chars.count % 2 == 1 { return [] }
    var bytes = [UInt8]()
    bytes.reserveCapacity(chars.count / 2)
    var i = 0
    while i < chars.count {
      guard let hi = VeilCryptoModule.hexDigit(chars[i]), let lo = VeilCryptoModule.hexDigit(chars[i + 1]) else { return [] }
      bytes.append(hi << 4 | lo)
      i += 2
    }
    return bytes
  }

  private static func hexDigit(_ c: UInt8) -> UInt8? {
    switch c {
    case 0x30...0x39: return c - 0x30
    case 0x41...0x46: return c - 0x41 + 10
    case 0x61...0x66: return c - 0x61 + 10
    default: return nil
    }
  }

  private static func bytesToHex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
  }
}
