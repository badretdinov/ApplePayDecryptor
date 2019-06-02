//
//  SecCertificate.swift
//  TokenDecrypt
//
//  Created by Oleg Badretdinov on 01/06/2019.
//  Copyright © 2019 Oleg Badretdinov. All rights reserved.
//

import Foundation

extension SecCertificate {
    static let applePayPrefix = "Apple Pay Payment Processing:"
    
    var isApplePay: Bool {
        if let name = SecCertificateCopySubjectSummary(self), String(name).hasPrefix(SecCertificate.applePayPrefix) {
            return true
        }
        
        return false
    }
}
