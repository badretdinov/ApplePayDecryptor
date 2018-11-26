//
//  JSONTokenViewController.swift
//  TokenDecrypt
//
//  Created by Oleg Badretdinov on 25/11/2018.
//  Copyright © 2018 Oleg Badretdinov. All rights reserved.
//

import Cocoa

fileprivate enum RowData {
    case nested(key: String, value:[RowData])
    case value(key: String, value:String)
}

class JSONTokenViewController: NSViewController, DecryptedTokenViewControllerProtocol {
    @IBOutlet weak var outlineView: NSOutlineView!
    
    var token: String = "" {
        didSet {
            self.updateRows()
            self.outlineView.reloadData()
        }
    }
    fileprivate var rows: [RowData] = []

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do view setup here.
    }
    
    fileprivate func updateRows() {
        if let jsonData = self.token.data(using: .utf8),
            let jsonObj = try? JSONSerialization.jsonObject(with: jsonData, options: []),
            let root = jsonObj as? [String : AnyObject] {
            self.rows = self.parseJson(root)
        }
    }
    
    fileprivate func parseJson(_ json: [String : AnyObject]) -> [RowData] {
        var out: [RowData] = []
        for (key, value) in json {
            if let json = value as? [String : AnyObject] {
                out.append(.nested(key: key, value: self.parseJson(json)))
            } else {
                out.append(.value(key: key, value: "\(value)"))
            }
        }
        return out
    }
}

extension JSONTokenViewController: NSOutlineViewDataSource {
    func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
        guard let item = item as? RowData else {
            return self.rows.count
        }
        
        switch item {
        case .nested(key: _, value: let rows):
            return rows.count
        default:
            return 0
        }
    }
    
    func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool {
        guard let item = item as? RowData else {
            return false
        }
        
        switch item {
        case .nested(key: _, value: _):
            return true
        default:
            return false
        }
    }
    
    func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
        guard let item = item as? RowData else {
            return self.rows[index]
        }
        
        switch item {
        case .nested(key: _, value: let rows):
            return rows[index]
        default:
            return NSNull()
        }
    }
}

extension JSONTokenViewController: NSOutlineViewDelegate {
    func outlineView(_ outlineView: NSOutlineView, viewFor tableColumn: NSTableColumn?, item: Any) -> NSView? {
        guard let column = tableColumn, let row = item as? RowData else {
            return nil
        }
        
        switch column.identifier {
        case .keyColumn:
            let view = outlineView.makeView(withIdentifier: .keyCell, owner: self) as? NSTableCellView
            
            switch row {
            case .value(key: let key, value: _):
                view?.textField?.stringValue = key
            case .nested(key: let key, value: _):
                view?.textField?.stringValue = key
            }
            
            return view
        case .valueColumn:
            let view = outlineView.makeView(withIdentifier: .valueCell, owner: self) as? NSTableCellView
            
            switch row {
            case .value(key: _, value: let value):
                view?.textField?.stringValue = value
            default:
                view?.textField?.stringValue = ""
            }
            
            return view
        default:
            return nil
        }
    }
}
