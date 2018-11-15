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
}

