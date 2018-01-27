Pod::Spec.new do |spec|
    spec.name = 'SignalProtocolSwift'
    spec.summary = 'A Swift implementation of the Signal Protocol API'
    spec.license = 'MIT'

    spec.version = '0.9'
    spec.source = {
        :git => 'https://github.com/christophhagen/SignalProtocolSwift.git',
        :tag => spec.version
    }

    spec.authors = { 'Christoph Hagen' => 'christoph@spacemasters.eu' } 
    spec.homepage = 'https://github.com/christophhagen/SignalProtocolSwift'

    spec.ios.deployment_target = '9.0'
    spec.osx.deployment_target = '10.9'
    spec.tvos.deployment_target = '9.0'
    spec.watchos.deployment_target = '4.0'

    spec.source_files = 'SignalProtocolSwift/**/*.{swift,h,c}'
    spec.public_header_files = ''

    spec.dependency 'SwiftProtobuf'
    spec.dependency 'Curve25519'
    spec.dependency 'CommonCryptoModule'
end