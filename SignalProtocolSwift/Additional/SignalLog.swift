//
//  SignalLog.swift
//  libsignal-protocol-swift
//
//  Created by User on 07.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

enum SignalLogLevel: Int, CustomStringConvertible {
    case error = 0
    case warning = 1
    case notice = 2
    case info = 3
    case debug = 4

    var description: String {
        switch self {
        case .error:
            return "ERROR"
        case .warning:
            return "WARNING"
        case .notice:
            return "NOTICE"
        case .info:
            return "INFO"
        case .debug:
            return "DEBUG"
        }
    }
}


func signalLog(level: SignalLogLevel, _ message: String, file: String = #file, function: String = #function, line: Int = #line) {
    print("[\(level)] \(message)")
    //print("[\(level)] \(file)(\(line)): \(function): \(message)")
}
