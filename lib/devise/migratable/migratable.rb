module Devise
  # Used to define the password encryption algorithm.
  mattr_accessor :encryptor
  @@encryptor = nil

  mattr_accessor :feature_class
  @@feature_class = nil

  mattr_accessor :feature_name
  @@feature_name = nil

  module Migratable
    module Encryptors
      InvalidHash = Class.new(StandardError)

      autoload :Base, 'devise/migratable/encryptors/base'
      autoload :Pbkdf2Sha512, 'devise/migratable/encryptors/pbkdf2_sha512'
    end
  end
end

Devise.add_module(:migratable, model: 'devise/migratable/model')
