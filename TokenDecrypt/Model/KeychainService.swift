//
//  KeychainService.swift
//  TokenDecrypt
//
//  Created by Oleg Badretdinov on 08/11/2018.
//  Copyright © 2018 Oleg Badretdinov. All rights reserved.
//

import Cocoa
import Security
import CommonCrypto

typealias ApplePayCertificate = (name: String, sertificate: SecCertificate, privateKey: SecKey?)

enum KeychainError: Error {
    case certificatesFetchError(code: OSStatus)
}

class KeychainService {
    fileprivate static let applePayPrefix = "Apple Pay Payment Processing:"
    
    func validCertificates() throws -> [ApplePayCertificate] {
        let certificates = try self.fetchCertificates()
        let filtered = self.filterCertificates(certificates)
        return try self.getKeyAndMapCertificates(filtered)
    }
    
    fileprivate func fetchCertificates() throws -> [SecCertificate] {
        var certsOpt :CFTypeRef?
        let keychainQuery = [kSecClass : kSecClassCertificate, kSecMatchLimit : kSecMatchLimitAll] as CFDictionary
        let status = SecItemCopyMatching(keychainQuery, &certsOpt)
        
        guard status == errSecSuccess, let certificates = certsOpt as? [SecCertificate] else {
            throw KeychainError.certificatesFetchError(code: status)
        }
        
        return certificates
    }
    
    fileprivate func filterCertificates(_ certificates: [SecCertificate])  -> [SecCertificate] {
        return certificates.filter({ (certificate) -> Bool in
            if let name = SecCertificateCopySubjectSummary(certificate), String(name).hasPrefix(KeychainService.applePayPrefix) {
                return true
            }
            
            return false
        })
    }
    
    fileprivate func getKeyAndMapCertificates(_ certificates: [SecCertificate]) throws -> [ApplePayCertificate] {
        return certificates.map({ (certificate) -> ApplePayCertificate in
            let fullName = SecCertificateCopySubjectSummary(certificate)
            var name = String(fullName ?? "").replacingOccurrences(of: KeychainService.applePayPrefix, with: "")
            
            var identity: SecIdentity?
            var privateKey: SecKey?
            SecIdentityCreateWithCertificate(nil, certificate, &identity)
            if let identity = identity {
                SecIdentityCopyPrivateKey(identity, &privateKey)
            }
            
            if privateKey == nil {
                name += " // no private key"
            }
            
            return (name, certificate, privateKey)
        })
    }
}
