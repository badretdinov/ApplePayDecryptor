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

struct ApplePayCertificate: Equatable {
    let name: String
    let certificate: SecCertificate
    let privateKey: SecKey?
    
    static func == (lhs: ApplePayCertificate, rhs: ApplePayCertificate) -> Bool {
        return lhs.name == rhs.name
    }
}

enum URLCertificateError: Error {
    case invalidFile
    case passwordRequired
    case invalidPassword
    case invalidCertificate
}
enum KeychainError: Error {
    case certificatesFetchError(code: OSStatus)
}

class KeychainService {
    func validCertificates() throws -> [ApplePayCertificate] {
        let certificates = try self.fetchCertificates()
        let filtered = self.filterCertificates(certificates)
        return try self.getKeyAndMapCertificates(filtered)
    }
    
    func importCertificate(fromUrl url: URL, password: String) throws -> [ApplePayCertificate] {
        let data = try Data(contentsOf: url)
        
        let dictionary: [ CFString : String ]
        if password.isEmpty {
            dictionary = [:]
        } else {
            dictionary = [kSecImportExportPassphrase : password]
        }
        
        var cfArray: CFArray?
        switch SecPKCS12Import(data as CFData, dictionary as CFDictionary, &cfArray) {
        case errSecPassphraseRequired:
            throw URLCertificateError.passwordRequired
        case errSecPkcs12VerifyFailure:
            throw URLCertificateError.invalidPassword
        default:
            break
        }
        
        guard let array = cfArray as? Array<[String : Any]> else {
            throw URLCertificateError.invalidFile
        }
        
        var certificates: [ApplePayCertificate] = []
        
        for i in 0..<array.count {
            let item = array[i]
            if let identity = item[kSecImportItemIdentity as String] {
                var cert: SecCertificate?
                SecIdentityCopyCertificate(identity as! SecIdentity, &cert)
                if let certificate = cert, certificate.isApplePay {
                    certificates.append(self.mapToApplePayCertificate(certificate))
                }
            }
        }
        
        guard !certificates.isEmpty else {
            throw URLCertificateError.invalidCertificate
        }
        
        return certificates
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
        return certificates.filter { $0.isApplePay }
    }
    
    fileprivate func getKeyAndMapCertificates(_ certificates: [SecCertificate]) throws -> [ApplePayCertificate] {
        return certificates.map { self.mapToApplePayCertificate($0) }
    }
    
    fileprivate func mapToApplePayCertificate(_ certificate: SecCertificate) -> ApplePayCertificate {
        let fullName = SecCertificateCopySubjectSummary(certificate)
        var name = String(fullName ?? "").replacingOccurrences(of: SecCertificate.applePayPrefix, with: "")
        
        var identity: SecIdentity?
        var privateKey: SecKey?
        SecIdentityCreateWithCertificate(nil, certificate, &identity)
        if let identity = identity {
            SecIdentityCopyPrivateKey(identity, &privateKey)
        }
        
        if privateKey == nil {
            name += " // no private key"
        }
        
        return ApplePayCertificate(name: name, certificate: certificate, privateKey: privateKey)
    }
}
