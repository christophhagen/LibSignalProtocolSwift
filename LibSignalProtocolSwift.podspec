Pod::Spec.new do |spec|
    spec.name = 'LibSignalProtocolSwift'
    spec.summary = 'A Swift implementation of the Signal Protocol'
    spec.license = 'MIT'

    spec.version = '1.3'
    spec.source = {
        :git => 'https://github.com/christophhagen/LibSignalProtocolSwift.git',
        :tag => spec.version
    }
    spec.swift_version = '5.0'
    spec.module_name  = 'SignalProtocol'

    spec.authors = { 'Christoph Hagen' => 'christoph@spacemasters.eu' }
    spec.homepage = 'https://github.com/christophhagen/LibSignalProtocolSwift'

    spec.ios.deployment_target = '9.0'
    spec.osx.deployment_target = '10.9'
    spec.tvos.deployment_target = '9.0'
    spec.watchos.deployment_target = '4.0'

    spec.source_files = 'Sources/**/*.{swift,h}'

    spec.dependency 'SwiftProtobuf'
    spec.dependency 'Curve25519'
    spec.dependency 'CommonCryptoModule'
end
