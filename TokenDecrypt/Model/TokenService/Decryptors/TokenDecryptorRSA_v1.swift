//
//  TokenDecryptorRSA_v1.swift
//  TokenDecrypt
//
//  Created by Oleg Badretdinov on 23/11/2018.
//  Copyright © 2018 Oleg Badretdinov. All rights reserved.
//

import Cocoa
import CryptoSwift

/**
 - Attention: Not tested. If you have any test data (RSA_v1), please contact me on github.
 */
class TokenDecryptorRSA_v1: TokenDecryptor {
    override func verifyToken() -> TokenSignatureVerificationStatus {
        return self.verifySignature(self.token.signature, wrappedKey: self.token.header.wrappedKey ?? "", tokenData: self.token.data, transactionId: self.token.header.transactionId, applicationData: self.token.header.applicationData)
    }
    
    override func decryptToken() -> TokenDecryptionStatus {
        return self.decryptData(dataStr: self.token.data, wrappedKey: self.token.header.wrappedKey ?? "", privateKey: self.privateKey)
    }
}

extension TokenDecryptorRSA_v1 {
    fileprivate func verifySignature(_ signature: String, wrappedKey: String, tokenData tokenDataStr: String, transactionId: String, applicationData appDataStr: String?) -> TokenSignatureVerificationStatus {
        guard let wrappedData = Data(base64Encoded: wrappedKey), let tokenData = Data(base64Encoded: tokenDataStr), let signatureData = Data(base64Encoded: signature) else {
            return .invalidSignature
        }
        let transactionIdData = transactionId.dataWithHexString()
        
        var verificationData = wrappedData + tokenData + transactionIdData
        if let appDataStr = appDataStr {
            let appData = appDataStr.dataWithHexString()
            verificationData = verificationData + appData
        }
        
        return self.verifySignatureData(signatureData, verificationData: verificationData)
    }
    
    fileprivate func decryptData(dataStr: String, wrappedKey: String, privateKey: SecKey) -> TokenDecryptionStatus {
        guard let data = Data(base64Encoded: dataStr) else {
            return .invalidData
        }
        
        guard let wrappedData = Data(base64Encoded: wrappedKey), let symmetricKey = self.symmetricKey(wrappedKey: wrappedData, privateKey: privateKey) else {
            return .invalidWrappedkey
        }
        
        var out: String = ""
        do {
            let gcm = GCM(iv: Array(repeating: 0, count: 16), mode: .combined)
            let aes = try AES(key: symmetricKey.bytes, blockMode: gcm, padding: .noPadding)
            let res = try aes.decrypt(data.bytes)
            out = String(bytes: res, encoding: .utf8) ?? ""
        } catch {
            return .decryptionFailed
        }
        
        return .dataDecrypted(out)
    }
    
    fileprivate func symmetricKey(wrappedKey: Data, privateKey: SecKey) -> Data? {
        var error: Unmanaged<CFError>!
        if let decrypted = SecKeyCreateDecryptedData(privateKey, SecKeyAlgorithm.rsaEncryptionOAEPSHA256, wrappedKey as CFData, &error), error == nil {
            return decrypted as Data
        } else {
            return nil
        }
    }
}
