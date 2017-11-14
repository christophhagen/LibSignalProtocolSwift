
abstract_target 'SignalProtocol' do
  # Comment the next line if you're not using Swift and don't want to use dynamic frameworks
  use_frameworks!

  # Pods for SignalProtocolSwift

  # Protocol Buffers in Swift for local storage and message exchange
  pod 'SwiftProtobuf'
  pod 'CommonCryptoModule', :git => 'https://github.com/christophhagen/CommonCryptoModule.git' 

  target 'SignalProtocolSwift' do
    platform :ios, '9.0'

  end

  target 'SignalProtocolSwiftMacOS' do 
    platform :osx, '10.9'

  end

  target 'SignalProtocolSwiftTests' do
    platform :ios, '8.0'
    inherit! :search_paths
    # Pods for testing
  end

end
