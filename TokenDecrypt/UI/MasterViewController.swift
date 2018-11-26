//
//  ViewController.swift
//  TokenDecrypt
//
//  Created by Oleg Badretdinov on 08/11/2018.
//  Copyright © 2018 Oleg Badretdinov. All rights reserved.
//

import Cocoa

class MasterViewController: NSViewController {
    @IBOutlet weak var popupButton: NSPopUpButton!
    @IBOutlet weak var statusLabel: NSTextField!
    @IBOutlet weak var decryptButton: NSButton!
    @IBOutlet var textView: NSTextView!
    
    fileprivate let tokenService = TokenService()
    fileprivate let service = KeychainService()
    fileprivate var certificates: [ApplePayCertificate] = []
    
    fileprivate var lastDecryptedToken = ""
    
    override func viewDidLoad() {
        super.viewDidLoad()
        self.updateCertificates(self)
    }
    
    @IBAction func updateCertificates(_ sender: Any) {
        do {
            self.certificates = try self.service.validCertificates()
            self.reloadPopUpButton()
        } catch {
            
        }
    }
    
    fileprivate func reloadPopUpButton() {
        self.popupButton.removeAllItems()
        self.popupButton.addItem(withTitle: "Select Certificate")
        let certNames = self.certificates.map { $0.name }
        self.popupButton.addItems(withTitles: certNames)
    }
    
    @IBAction func decryptToken(_ sender: Any) {
        guard self.popupButton.indexOfSelectedItem > 0 else {
            self.showAlert(title: "Please select ApplePay certificate", subtitle: "")
            return
        }
        
        let cert = self.certificates[popupButton.indexOfSelectedItem - 1]
        guard let pk = cert.privateKey else {
            self.showAlert(title: "Selected certificate doesn't have a private key", subtitle: "Please select certificate with private key. You could check your certificates and private keys in keychain application.")
            return
        }
        
        guard let decryptor = self.tokenService.tokenDecryptor(self.textView.string, certificate: cert.certificate, privateKey: pk) else {
            self.showAlert(title: "Invalid token format", subtitle: "Please enter valid token and try again")
            return
        }
        
        let verifyStatus = decryptor.verifyToken()
        
        guard verifyStatus == .valid else {
            self.showAlert(forVerificationStatus: verifyStatus)
            return
        }
        
        let decryptionStatus = decryptor.decryptToken()
        
        switch decryptionStatus {
        case .dataDecrypted(let token):
            self.lastDecryptedToken = token
            self.performSegue(withIdentifier: .decryptedTokenSegue, sender: nil)
        default:
            self.showAlert(forDecryptionStatus: decryptionStatus)
        }
    }
}

extension MasterViewController: NSTextViewDelegate {
    func textDidChange(_ notification: Notification) {
        self.validateToken()
    }
    
    fileprivate func validateToken() {
        guard !self.textView.string.isEmpty else {
            self.statusLabel.stringValue = "Enter ApplePay Token"
            return
        }
        
        self.statusLabel.stringValue = self.tokenService.isTokenValid(self.textView.string) ? "Valid ApplePay token" : "Invalid ApplePay token"
    }
}

extension MasterViewController {
    fileprivate func showAlert(forVerificationStatus status: TokenSignatureVerificationStatus) {
        self.showAlert(title: "Token signature verification has been failed", subtitle: self.description(forVerificationStatus: status))
    }
    
    fileprivate func showAlert(forDecryptionStatus status: TokenDecryptionStatus) {
        self.showAlert(title: "Token decryption has been failed", subtitle: self.description(forVerificationStatus: status))
    }
    
    fileprivate func showAlert(title: String, subtitle: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = subtitle
        alert.alertStyle = .warning
        alert.runModal()
    }
    
    fileprivate func description(forVerificationStatus status: TokenSignatureVerificationStatus) -> String {
        switch status {
        case .invalidTokenFormat:
            return "Invalid token format"
        case .invalidSignature:
            return "Invalid token's signature format"
        case .noSignatureCertificates:
            return "No certificates has been found in signature"
        case .certificatesVerificationFailed:
            return "Leaf and Intermidiate certificates verification has been failed"
        case .signatureVerificationFailed:
            return "Signature verification has been failed failed"
        default:
            return ""
        }
    }
    
    fileprivate func description(forVerificationStatus status: TokenDecryptionStatus) -> String {
        switch status {
        case .invalidToken:
            return "Invalid token format"
        case .invalidData:
            return "Invalid token data"
        case .invalidCertificate:
            return "Invalid certificate"
        case .invalidEphemeralKey:
            return "Invalid ephemeral key"
        case .sharedSecretGenerationFailed:
            return "Shared secret generation has been failed"
        case .decryptionFailed:
            return "Decryption process has been failed"
        default:
            return ""
        }
    }
    
    override func prepare(for segue: NSStoryboardSegue, sender: Any?) {
        guard let identifier = segue.identifier else {
            return
        }
        
        switch identifier {
        case .decryptedTokenSegue:
            if var dest = segue.destinationController as? DecryptedTokenViewControllerProtocol {
                dest.token = self.lastDecryptedToken
            }
        default:
            break
        }
    }
}
