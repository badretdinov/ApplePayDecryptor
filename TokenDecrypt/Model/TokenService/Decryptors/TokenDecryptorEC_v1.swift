//
//  TokenDecryptorEC_v1.swift
//  TokenDecrypt
//
//  Created by Oleg Badretdinov on 23/11/2018.
//  Copyright © 2018 Oleg Badretdinov. All rights reserved.
//

import Cocoa
import CommonCrypto
import CryptoSwift

class TokenDecryptorEC_v1: TokenDecryptor {
    override func verifyToken() -> TokenSignatureVerificationStatus {
        return self.verifySignature(self.token.signature, ephemeralKey: self.token.header.ephemeralPublicKey ?? "", tokenData: self.token.data, transactionId: self.token.header.transactionId, applicationData: self.token.header.applicationData)
    }
    
    override func decryptToken() -> TokenDecryptionStatus {
        return self.decryptData(dataStr: token.data, ephemeral: token.header.ephemeralPublicKey ?? "", privateKey: privateKey, certificate: certificate)
    }
}

extension TokenDecryptorEC_v1 {
    fileprivate func verifySignature(_ signature: String, ephemeralKey: String, tokenData tokenDataStr: String, transactionId: String, applicationData appDataStr: String?) -> TokenSignatureVerificationStatus {
        guard let ephData = Data(base64Encoded: ephemeralKey), let tokenData = Data(base64Encoded: tokenDataStr), let signatureData = Data(base64Encoded: signature) else {
            return .invalidSignature
        }
        let transactionIdData = transactionId.dataWithHexString()
        
        var verificationData = ephData + tokenData + transactionIdData
        if let appDataStr = appDataStr {
            let appData = appDataStr.dataWithHexString()
            verificationData = verificationData + appData
        }
        
        return self.verifySignatureData(signatureData, verificationData: verificationData)
    }
    
    fileprivate func decryptData(dataStr: String, ephemeral: String, privateKey: SecKey, certificate: SecCertificate) -> TokenDecryptionStatus {
        guard let data = Data(base64Encoded: dataStr) else {
            return .invalidData
        }
        
        guard let ephemeralData = Data(base64Encoded: ephemeral), let ephemeralKey = SecKeyCreateFromData([kSecAttrKeyType : kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass : kSecAttrKeyClassPublic] as CFDictionary, ephemeralData as CFData, nil) else {
            return .invalidEphemeralKey
        }
        
        guard let sharedSecret = self.sharedSecret(privateKey: privateKey, ephemeralKey: ephemeralKey) else {
            return .sharedSecretGenerationFailed
        }
        
        
        guard let merchantId = self.merchantId(fromCertificate: certificate) else {
            return .invalidCertificate
        }
        let kdf = self.kdfInfo(merchantId: merchantId)
        let symmetric = self.symmetricKey(kdfInfo: kdf, sharedSecret: sharedSecret)
        
        var out: String = ""
        do {
            let gcm = GCM(iv: Array(repeating: 0, count: 16), mode: .combined)
            let aes = try AES(key: symmetric.bytes, blockMode: gcm, padding: .noPadding)
            let res = try aes.decrypt(data.bytes)
            out = String(bytes: res, encoding: .utf8) ?? ""
        } catch {
            return .decryptionFailed
        }
        
        return .dataDecrypted(out)
    }
    
    /**
     Generates shared secret using Elliptic Curve Diffie-Hellman
     
     - Parameters:
     - privateKey: Merchant private key
     - ephemeralKey: Ephemeral public key from token
     */
    fileprivate func sharedSecret(privateKey: SecKey, ephemeralKey: SecKey) -> Data? {
        let dict = [:] as CFDictionary
        var error: Unmanaged<CFError>!
        if let res = SecKeyCopyKeyExchangeResult(privateKey, .ecdhKeyExchangeStandard, ephemeralKey, dict, &error), error == nil {
            return res as Data
        } else {
            return nil
        }
    }
    
    /**
     Retrives merchant id from selected certificate
     */
    fileprivate func merchantId(fromCertificate certificate: SecCertificate) -> String? {
        guard let certValues = SecCertificateCopyValues(certificate, [OID.subjectName.rawValue] as CFArray, nil) as? [String : AnyObject], let certSubjectContainer = certValues[OID.subjectName.rawValue] as? [String : AnyObject], let subjectsArry = certSubjectContainer["value"] as? [[String : Any]] else {
            return nil
        }
        
        guard let merchantObject = subjectsArry.first(where: { ($0["label"] as? String) == OID.merchant.rawValue }), let merchant = merchantObject["value"] as? String else {
            return nil
        }
        
        return merchant
    }
    
    /**
     Generates key derivation function information
     - Parameters:
     - merchantId: Merchant id from certificate
     */
    fileprivate func kdfInfo(merchantId: String) -> Data {
        let data = Data(merchantId.utf8)
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        let dataBytes = [UInt8](data)
        CC_SHA256(dataBytes, CC_LONG(dataBytes.count), &hash)
        let keyData = Data(bytes: hash)
        let firstData = Data("\rid-aes256-GCMApple".utf8)
        return firstData + keyData
    }
    
    /**
     Generates symmetric key using kdf described in NIST SP 800-56A, section 5.8.1
     */
    fileprivate func symmetricKey(kdfInfo:Data, sharedSecret: Data) -> Data {
        let begin = "\u{0}\u{0}\u{0}\u{1}".data(using: .utf8)!
        let data = begin + sharedSecret + kdfInfo
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        let dataBytes = [UInt8](data)
        CC_SHA256(dataBytes, CC_LONG(dataBytes.count), &hash)
        let keyData = Data(bytes: hash)
        return keyData
    }
}
