//
//  ApplePayToken.swift
//  TokenDecrypt
//
//  Created by Oleg Badretdinov on 10/11/2018.
//  Copyright © 2018 Oleg Badretdinov. All rights reserved.
//

import Cocoa

enum ApplePayTokenVersion: String, Decodable {
    case EC_v1 = "EC_v1"
    case RSA_v1 = "RSA_v1"
}

struct ApplePayToken: Decodable {
    let version: ApplePayTokenVersion
    let signature: String
    let data: String
    let header: ApplePayTokenHeader
}

struct ApplePayTokenHeader: Decodable {
    let applicationData: String?
    let transactionId: String
    let publicKeyHash: String
    let ephemeralPublicKey: String
}
