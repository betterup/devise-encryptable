module Devise
  # Used to define the password encryption algorithm.
  mattr_accessor :encryptor
  @@encryptor = nil

  mattr_accessor :override_existing_password_hash
  @@override_existing_password_hash = nil


  # Sets override_existing_password_hash block
  #
  #  Devise.setup do |config|
  #
  #    config.override_existing_password_hash_check do |user|
  #      Features.active?(:override_existing_password_hash_using_encryptor, user)
  #    end
  #  end
  def self.override_existing_password_hash_check(&block)
    @@override_existing_password_hash = block
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
