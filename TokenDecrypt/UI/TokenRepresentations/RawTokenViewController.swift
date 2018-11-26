//
//  RawTokenViewController.swift
//  TokenDecrypt
//
//  Created by Oleg Badretdinov on 25/11/2018.
//  Copyright © 2018 Oleg Badretdinov. All rights reserved.
//

import Cocoa

class RawTokenViewController: NSViewController, DecryptedTokenViewControllerProtocol {
    @IBOutlet var textView: NSTextView!
    
    var token: String = ""
    
    fileprivate var formatedToken: String {
        if let jsonData = self.token.data(using: .utf8),
            let jsonObj = try? JSONSerialization.jsonObject(with: jsonData, options: []),
            let data = try? JSONSerialization.data(withJSONObject: jsonObj, options: .prettyPrinted),
            let out = String(data: data, encoding: .utf8) {
            return out
        } else {
            return self.token
        }
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        self.updateTextView()
    }
    
    
    fileprivate func updateTextView() {
        self.textView.string = self.formatedToken
    }
}
