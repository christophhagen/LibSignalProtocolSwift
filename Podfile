use_frameworks!
use_modular_headers!

target 'TestsHost' do

  # Pods for LibSignalProtocolSwift
  pod 'LibSignalProtocolSwift', :path => "./"
  # Protocol Buffers in Swift
  pod 'SwiftProtobuf', '~> 1.5.0'

  # Elliptic Curve functions
#  pod 'Curve25519', '~> 1.1'
  pod 'Curve25519', :path => "/Users/lidawen/Documents/work/IM5/signal-archive/VoderXCurve25519"
  pod 'CCurve25519', :path => "/Users/lidawen/Documents/work/IM5/signal-archive/VoderXCCurve25519"
  
  target 'TestsHostTests' do
    inherit! :search_paths
  end
end

post_install do |installer|
#  fix_arm64_for_sim(installer)
  fix_targets_version(installer)
  fix_xcode14_pods_sign(installer)
end

def fix_arm64_for_sim(installer)
  installer.pods_project.build_configurations.each do |config|
    config.build_settings["EXCLUDED_ARCHS[sdk=iphonesimulator*]"] = "arm64"
  end
end

def fix_targets_version(installer)
  installer.pods_project.targets.each do |target|
    target.build_configurations.each do |config|
      config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = '13.0'
    end
  end
end

def fix_xcode14_pods_sign(installer)
  installer.pods_project.targets.each do |target|
      target.build_configurations.each do |config|
          config.build_settings['CODE_SIGN_IDENTITY'] = ''
      end
  end
end
