use_frameworks!

abstract_target 'LibSignalProtocolSwift' do

  # Pods for LibSignalProtocolSwift

  # Protocol Buffers in Swift
  pod 'SwiftProtobuf'

  # Elliptic Curve functions
  pod 'Curve25519'

  # Cryptographic functions powered by CommonCrypto
  pod 'CommonCryptoModule', '~> 1.0.2'


  # iOS
  target 'LibSignalProtocolSwift iOS' do
    platform :ios, '9.0'
    
    target 'LibSignalProtocolSwift Tests' do
      inherit! :search_paths
      # Pods for testing

    end
  end


  # macOS
  target 'LibSignalProtocolSwift macOS' do
    platform :osx, '10.9'
    # Pods for LibSignalProtocolSwift macOS
  end


  # tvOS
  target 'LibSignalProtocolSwift tvOS' do
    platform :tvos, '9.0'
    # Pods for LibSignalProtocolSwift tvOS
  end


  # watchOS
  target 'LibSignalProtocolSwift watchOS' do
    platform :watchos, '4.0'
    # Pods for LibSignalProtocolSwift watchOS
  end
end
