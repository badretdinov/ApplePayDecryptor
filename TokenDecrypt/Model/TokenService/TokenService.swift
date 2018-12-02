//
//  TokenService.swift
//  TokenDecrypt
//
//  Created by Oleg Badretdinov on 15/11/2018.
//  Copyright © 2018 Oleg Badretdinov. All rights reserved.
//

import Cocoa

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
    case invalidWrappedkey
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
     Create decryptor for token. 
     */
    func tokenDecryptor(_ token: String, certificate: SecCertificate, privateKey: SecKey) -> TokenDecryptor? {
        guard let token = self.token(fromString: token) else {
            return nil
        }
        
        switch token.version {
        case .EC_v1:
            return TokenDecryptorEC_v1(token, certificate: certificate, privateKey: privateKey)
        case .RSA_v1:
            return TokenDecryptorRSA_v1(token, certificate: certificate, privateKey: privateKey)
        }
    }
    
    /**
     Decrypt base64 ApplePay token string into struct
     
     - Parameters:
     - fromString: Base64 encoded ApplePay token string
     
     - Returns: Decoded ApplePay token struct
     */
    fileprivate func token(fromString tokenStr: String) -> ApplePayToken? {
        if let tokenData = (Data(base64Encoded: tokenStr) ?? tokenStr.data(using: .utf8)), let token = try? JSONDecoder().decode(ApplePayToken.self, from: tokenData) {
            return token
        } else {
            return nil
        }
    }
}
