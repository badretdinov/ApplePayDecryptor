//
//  TokenDecryptorProtocol.swift
//  TokenDecrypt
//
//  Created by Oleg Badretdinov on 22/11/2018.
//  Copyright © 2018 Oleg Badretdinov. All rights reserved.
//

import Foundation

internal enum OID: String {
    case leaf = "1.2.840.113635.100.6.29"
    case intermidiate = "1.2.840.113635.100.6.2.14"
    case subjectName = "2.16.840.1.113741.2.1.1.1.8"
    case merchant = "0.9.2342.19200300.100.1.1"
}

class TokenDecryptor {
    internal let token: ApplePayToken
    internal let certificate: SecCertificate
    internal let privateKey: SecKey
    
    init(_ token: ApplePayToken, certificate: SecCertificate, privateKey: SecKey) {
        self.token = token
        self.certificate = certificate
        self.privateKey = privateKey
    }
    
    /**
     ApplePay signature verification
     */
    func verifyToken() -> TokenSignatureVerificationStatus {
        preconditionFailure("This method must be overridden")
    }
    
    /**
     Decrypt ApplePay token data
     */
    func decryptToken() -> TokenDecryptionStatus {
        preconditionFailure("This method must be overridden")
    }
    
    /**
     Step 1 from [Payment Token Format Reference](https://developer.apple.com/library/archive/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html)
     */
    internal func verifySignatureData(_ signatureData: Data, verificationData: Data) -> TokenSignatureVerificationStatus {
        let signature = [UInt8](signatureData)
        
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
