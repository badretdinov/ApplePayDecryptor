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

enum TokenVerificationStatus {
    case invalidTokenFormat
    case invalidSignature
    case noSignatureCertificates
    case certificatesVerificationFailed
    case signatureVerificationFailed
    case valid
}

class TokenService {
    func isTokenValid(_ tokenStr: String) -> Bool {
        return self.token(fromString: tokenStr) != nil
    }
    
    func verifyToken(_ tokenStr: String) -> TokenVerificationStatus {
        guard let token = self.token(fromString: tokenStr) else { return .invalidTokenFormat }
        
        return self.verifySignature(token.signature, ephemerialKey: token.header.ephemeralPublicKey, tokenData: token.data, transactionId: token.header.transactionId, applicationData: token.header.applicationData)
    }
}

extension TokenService {
    fileprivate func token(fromString tokenStr: String) -> ApplePayToken? {
        if let tokenData = Data(base64Encoded: tokenStr), let token = try? JSONDecoder().decode(ApplePayToken.self, from: tokenData) {
            return token
        } else {
            return nil
        }
    }
    
    fileprivate func verifySignature(_ signature: String, ephemerialKey: String, tokenData tokenDataStr: String, transactionId: String, applicationData appDataStr: String?) -> TokenVerificationStatus {
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
        
        var stat = CMSSignerStatus.needsDetachedContent
        var certResult: OSStatus = 0
        CMSDecoderCopySignerStatus(decoder, 0, SecPolicyCreateBasicX509(), true, &stat, nil, &certResult)
        
        guard certResult == 0 else { return .certificatesVerificationFailed }
        guard stat == .valid else { return .signatureVerificationFailed }
        
        return .valid
    }
}
