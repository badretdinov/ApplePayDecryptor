//
//  ViewController.swift
//  TokenDecrypt
//
//  Created by Oleg Badretdinov on 08/11/2018.
//  Copyright © 2018 Oleg Badretdinov. All rights reserved.
//

import Cocoa

class ViewController: NSViewController {
    @IBOutlet weak var popupButton: NSPopUpButton!
    @IBOutlet weak var statusLabel: NSTextField!
    @IBOutlet weak var decryptButton: NSButton!
    @IBOutlet var textView: NSTextView!
    
    fileprivate let tokenService = TokenService()
    fileprivate let service = KeychainService()
    fileprivate var certificates: [ApplePayCertificate] = []
    
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
        
    }
}

extension ViewController: NSTextViewDelegate {
    func textDidChange(_ notification: Notification) {
        self.verifyToken()
    }
    
    fileprivate func verifyToken() {
        let tokenStr = self.textView.string
        self.tokenService.verifyToken(tokenStr)
    }
}
