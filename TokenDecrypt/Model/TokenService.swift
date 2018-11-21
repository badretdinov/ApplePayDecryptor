//
//  TokenService.swift
//  TokenDecrypt
//
//  Created by Oleg Badretdinov on 15/11/2018.
//  Copyright © 2018 Oleg Badretdinov. All rights reserved.
//

import Cocoa
import CommonCrypto
import CryptoSwift

fileprivate enum OID: String {
    case leaf = "1.2.840.113635.100.6.29"
    case intermidiate = "1.2.840.113635.100.6.2.14"
    case subjectName = "2.16.840.1.113741.2.1.1.1.8"
    case merchant = "0.9.2342.19200300.100.1.1"
}

enum TokenSignatureVerificationStatus {
    case invalidTokenFormat
    case invalidSignature
    case noSignatureCertificates
    case certificatesVerificationFailed
    case signatureVerificationFailed
    case valid
}

enum TokenDecryptionStatus {
    case invalidToken
    case invalidData
    case invalidEphemeralKey
    case invalidCertificate
    case sharedSecretGenerationFailed
    case decryptionFailed
    case dataDecrypted(String)
}

class TokenService {
    /**
     Simple token validation. Token will be checked only for base64 and struct decoding.
     */
    func isTokenValid(_ tokenStr: String) -> Bool {
        return self.token(fromString: tokenStr) != nil
    }
    
    /**
     ApplePay signature verification
     
     - Parameters:
        - tokenStr: Base64 encoded ApplePay token string
     */
    func verifyToken(_ tokenStr: String) -> TokenSignatureVerificationStatus {
        guard let token = self.token(fromString: tokenStr) else { return .invalidTokenFormat }
        
        return self.verifySignature(token.signature, ephemeralKey: token.header.ephemeralPublicKey, tokenData: token.data, transactionId: token.header.transactionId, applicationData: token.header.applicationData)
    }
    
    /**
     Decrypt ApplePay token data
     
     - Parameters:
        - tokenStr: Base64 encoded ApplePay token string
        - certificate: ApplePay merchant certificate
        - privateKey: Private key associated with certificate
     */
    func decryptToken(_ tokenStr: String, certificate: SecCertificate, privateKey: SecKey) -> TokenDecryptionStatus {
        guard let token = self.token(fromString: tokenStr) else { return .invalidToken }
        return self.decryptData(dataStr: token.data, ephemeral: token.header.ephemeralPublicKey, privateKey: privateKey, certificate: certificate)
    }
    
    /**
     Decrypt base64 ApplePay token string into struct
     
     - Parameters:
     - fromString: Base64 encoded ApplePay token string
     
     - Returns: Decoded ApplePay token struct
     */
    fileprivate func token(fromString tokenStr: String) -> ApplePayToken? {
        if let tokenData = Data(base64Encoded: tokenStr), let token = try? JSONDecoder().decode(ApplePayToken.self, from: tokenData) {
            return token
        } else {
            return nil
        }
    }
}

//verification
extension TokenService {
    /**
     Step 1 from [Payment Token Format Reference](https://developer.apple.com/library/archive/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html)
     
     - Parameters:
        - signature: Base64 encoded signature
        - ephemeralKey: Base64 encoded signature
        - transactionId: Hexadecimal representation of transaction id
        - applicationData: Hex encdoded SHA–256 hash of request object.
     */
    fileprivate func verifySignature(_ signature: String, ephemeralKey: String, tokenData tokenDataStr: String, transactionId: String, applicationData appDataStr: String?) -> TokenSignatureVerificationStatus {
        guard let ephData = Data(base64Encoded: ephemeralKey), let tokenData = Data(base64Encoded: tokenDataStr), let signatureData = Data(base64Encoded: signature) else {
            return .invalidSignature
        }
        let signature = [UInt8](signatureData)
        let transactionIdData = transactionId.dataWithHexString()
        
        var verificationData = ephData + tokenData + transactionIdData
        if let appDataStr = appDataStr {
            let appData = appDataStr.dataWithHexString()
            verificationData = verificationData + appData
        }
        
        var decoder: CMSDecoder!
        CMSDecoderCreate(&decoder)
        CMSDecoderUpdateMessage(decoder, signature, signature.count)
        CMSDecoderFinalizeMessage(decoder)
        CMSDecoderSetDetachedContent(decoder, verificationData as CFData)
        
        var certificates: CFArray?
        CMSDecoderCopyAllCerts(decoder, &certificates)
        guard let certs = certificates as? [SecCertificate] else { return .noSignatureCertificates }
        var leaf: SecCertificate!
        var intermidiate: SecCertificate!
        for cert in certs {
            if let values = SecCertificateCopyValues(cert, [OID.leaf.rawValue, OID.intermidiate.rawValue] as CFArray, nil) as? [String : Any] {
                if values.keys.contains(OID.leaf.rawValue), leaf == nil {
                    leaf = cert
                }
                
                if values.keys.contains(OID.intermidiate.rawValue), intermidiate == nil {
                    intermidiate = cert
                }
            }
            
            if leaf != nil, intermidiate != nil {
                break
            }
        }
        
        guard leaf != nil, intermidiate != nil else { return .noSignatureCertificates }
        
        var signerStatus = CMSSignerStatus.needsDetachedContent
        var certResult: OSStatus = 0
        CMSDecoderCopySignerStatus(decoder, 0, SecPolicyCreateBasicX509(), true, &signerStatus, nil, &certResult)
        
        guard certResult == 0 else { return .certificatesVerificationFailed }
        guard signerStatus == .valid else { return .signatureVerificationFailed }
        
        return .valid
    }
}

extension TokenService {
    /**
     Decrypt ApplePay token data
     
     - Parameters:
     - dataStr: Base64 encoded ApplePay token data
     - ephemeral: Ephemeral public key from ApplePay token
     - certificate: ApplePay merchant certificate
     - privateKey: Private key associated with certificate
     */
    
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
            let gcm = GCM(iv: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], mode: .combined)
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
        _ = data.withUnsafeBytes {
            CC_SHA256($0, CC_LONG(data.count), &hash)
        }
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
        _ = data.withUnsafeBytes {
            CC_SHA256($0, CC_LONG(data.count), &hash)
        }
        
        let keyData = Data(bytes: hash)
        return keyData
    }
}
