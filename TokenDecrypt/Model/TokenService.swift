//
//  TokenService.swift
//  TokenDecrypt
//
//  Created by Oleg Badretdinov on 15/11/2018.
//  Copyright © 2018 Oleg Badretdinov. All rights reserved.
//

import Cocoa

fileprivate enum OID: String {
    case leaf = "1.2.840.113635.100.6.29"
    case intermidiate = "1.2.840.113635.100.6.2.14"
}

enum TokenSignatureVerificationStatus {
    case invalidTokenFormat
    case invalidSignature
    case noSignatureCertificates
    case certificatesVerificationFailed
    case signatureVerificationFailed
    case valid
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
        
        return self.verifySignature(token.signature, ephemerialKey: token.header.ephemeralPublicKey, tokenData: token.data, transactionId: token.header.transactionId, applicationData: token.header.applicationData)
    }
}

extension TokenService {
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
    
    /**
     Step 1 from [Payment Token Format Reference](https://developer.apple.com/library/archive/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html)
     
     - Parameters:
        - signature: Base64 encoded signature
        - ephemerialKey: Base64 encoded signature
        - transactionId: Hexadecimal representation of transaction id
        - applicationData: Hex encdoded SHA–256 hash of request object.
     */
    fileprivate func verifySignature(_ signature: String, ephemerialKey: String, tokenData tokenDataStr: String, transactionId: String, applicationData appDataStr: String?) -> TokenSignatureVerificationStatus {
        guard let ephData = Data(base64Encoded: ephemerialKey), let tokenData = Data(base64Encoded: tokenDataStr), let signatureData = Data(base64Encoded: signature) else {
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
                if values.keys.contains(OID.leaf.rawValue), leaf != nil {
                    leaf = cert
                }
                
                if values.keys.contains(OID.intermidiate.rawValue), intermidiate != nil {
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
