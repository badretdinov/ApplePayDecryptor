//
//  DecryptedViewController.swift
//  TokenDecrypt
//
//  Created by Oleg Badretdinov on 25/11/2018.
//  Copyright © 2018 Oleg Badretdinov. All rights reserved.
//

import Cocoa

protocol DecryptedTokenViewControllerProtocol {
    var token: String { get set }
}

class DecryptedViewController: NSTabViewController, DecryptedTokenViewControllerProtocol {
    var token = ""
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        self.updateSubControllers()
    }
    
    fileprivate func updateSubControllers() {
        for item in self.tabViewItems {
            if var ctrl = item.viewController as? DecryptedTokenViewControllerProtocol {
                ctrl.token = self.token
            }
        }
    }
}
