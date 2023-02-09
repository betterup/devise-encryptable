module Devise
  # Used to define the password encryption algorithm.
  mattr_accessor :encryptor
  @@encryptor = nil

  # block to be evaluated to determine wether to validate using encryptor
  mattr_accessor :enable_validation
  @@enable_validation = nil

  # Sets enable_validation block
  #
  #  Devise.setup do |config|
  #
  #    config.validate_using_encryptor do |user|
  #      Features.active?(:enable_pbkdf2_validation, user)
  #    end
  #  end
  def self.validate_using_encryptor(&block)
    @@enable_validation = block
  end

  module Migratable
    module Encryptors
      InvalidHash = Class.new(StandardError)

      autoload :Base, 'devise/migratable/encryptors/base'
      autoload :Pbkdf2Sha512, 'devise/migratable/encryptors/pbkdf2_sha512'
    end
  end
end

Devise.add_module(:migratable, model: 'devise/migratable/model')
