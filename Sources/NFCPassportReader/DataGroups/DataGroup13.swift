//
//  DataGroup13.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation

// SecurityInfos ::= SET of SecurityInfo
// SecurityInfo ::= SEQUENCE {
//    protocol OBJECT IDENTIFIER,
//    requiredData ANY DEFINED BY protocol,
//    optionalData ANY DEFINED BY protocol OPTIONAL
@available(iOS 13, macOS 10.15, *)
public class DataGroup13 : DataGroup {
    private var asn1 : ASN1Item!
    
    public override var datagroupType: DataGroupId { .DG13 }
    
    public private(set) var rawData13 : String?
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
    }
    
    override func parse(_ data: [UInt8]) throws {
        let p = SimpleASN1DumpParser()
        asn1 = try p.parse(data: Data(body))
        
        let asn1Data = try OpenSSLUtils.ASN1Parse( data: Data(body) )
        
        var extractedValues = [String]()
        let lines = asn1Data.components(separatedBy: "\n")

        for line in lines {
            if line.contains("UTF8STRING") || line.contains("PRINTABLESTRING") {
                if let range = line.range(of: #":[^:]+$"#, options: .regularExpression) {
                    let value = String(line[range]).trimmingCharacters(in: CharacterSet(charactersIn: ": "))
                    extractedValues.append(value)
                }
            }
        }

        rawData13 = extractedValues.joined(separator: ", ")
    }
    
}
