use_frameworks!

abstract_target 'SignalProtocolSwift' do



  # Pods for SignalProtocolSwift

  # Protocol Buffers in Swift
  pod 'SwiftProtobuf'

  # Elliptic Curve functions
  pod 'Curve25519', :git => 'https://github.com/christophhagen/Curve25519'

  # Cryptographic functions powered by CommonCrypto
  pod 'CommonCryptoModule', '~> 1.0.2'



  # iOS
  target 'SignalProtocolSwift iOS' do
    platform :ios, '9.0'
    
    target 'SignalProtocolSwift Tests' do
      inherit! :search_paths
      # Pods for testing

    end
  end


  # macOS
  target 'SignalProtocolSwift macOS' do
    platform :osx, '10.9'
    # Pods for SignalProtocolSwift macOS
  end


  # tvOS
  target 'SignalProtocolSwift tvOS' do
    platform :tvos, '9.0'
    # Pods for SignalProtocolSwift tvOS
  end


  # watchOS
  target 'SignalProtocolSwift watchOS' do
    platform :watchos, '4.0'
    # Pods for SignalProtocolSwift watchOS
  end
end
