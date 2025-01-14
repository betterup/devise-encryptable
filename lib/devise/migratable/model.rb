require 'devise/strategies/database_authenticatable'
require 'bcrypt'

module Devise
  module Models
    # Migratable module adds support to help gradually migrating default devise hashing to
    # a new encryptor controlled by feature flags. If you start from a new system, or you don't
    # need to gradually migrate / rollback the process, then you should be using `devise-encrytable`
    # directly.
    #
    # This module requires a new database column `encrypted_password_migrate_to` to store the new hashed
    # password. So for each password set or validate, it would start storing the new hashed password
    # in encrypted_password_migrate_to. If feature flag enabled, it would start validating against the
    # encrypted_password_migrate_to. The goal of this module is to allow us gracefully migrate existing password
    # hashing with the ability to rollback or turn on and off through feature flags.
    #
    # Once all users have passwords hashed in the encrypted_password_migrate_to, you could run a migration
    # to copy/swap data from encrypted_password_migrate_to to encrypted_password, at the same time, replace
    # this module with `devise-encrytable`.
    #
    # == Options
    #
    # Migratable adds the following options to devise_for:
    #
    #   * +pepper+: a random string used to provide a more secure hash.
    #
    #   * +encryptor+: the encryptor going to be used. By default is nil.
    #
    #   * +feature_class+: feature class used to check wether validating password using new encryptor.
    #
    #   * +feature_name+: feature name will be passed to feature_class.active?(feature_name, user_model).
    #
    # == Examples
    #    # with feature disabled
    #    User.find(1).valid_password?('password123')
    #    #=> returns true/false
    #    #=> if true will start saving new hashed password to encrypted_password_migrate_to using encryptor
    #    #=> still using encrypted_password to validate because feature not enabled
    #
    #    # with feature enabled
    #    User.find(1).valid_password?('password123')
    #    #=> returns true/false
    #    #=> validate against encrypted_password_migrate_to using encryptor, fallback to old one if encrypted_password_migrate_to not present
    module Migratable
      extend ActiveSupport::Concern

      def self.required_fields(_klass)
        [:encrypted_password_migrate_to]
      end

      # Generates new password for the new encryptor
      # generate password of the old one using super
      def password=(new_password)
        unless override_existing_password_hash_enabled?
          self.encrypted_password_migrate_to = generate_digest_for_password(new_password)
        end
        super
      end

      # Validates the password considering the salt.
      def valid_password?(password)
        return false if encrypted_password.blank?

        if valid_encryptor_hash?
          valid_password_using_encryptor?(password)
        else
          result = super
          update_encrypted_password_hash(password) if result
          result
        end
      end

      def valid_encryptor_hash?
        encryptor_class.valid_hash?(encrypted_password)
      end

      # redefine serializable_hash to prevent encrypted_password_migrate_to leaking
      def serializable_hash(options = {})
        options[:except] ||= []
        options[:except].push(:encrypted_password_migrate_to)
        super(options)
      end

      protected

      def password_digest(password)
        override_existing_password_hash_enabled? ? generate_digest_for_password(password) : super
      end

      def update_encrypted_password_hash(password)
        return if new_record?

        column_name = override_existing_password_hash_enabled? ? :encrypted_password : :encrypted_password_migrate_to
        update_column(column_name, generate_digest_for_password(password))
      rescue StandardError => e # capture StandardError instead of ActiveRecordError to play safe
        log_error("Failed to update_column #{column_name}", e)
      end

      def generate_digest_for_password(password)
        encryptor_class.digest(password,
                               self.class.stretches,
                               self.class.password_salt,
                               self.class.pepper)
      end

      def override_existing_password_hash_enabled?
        self.class.override_existing_password_hash&.call(self)
      end

      def valid_password_using_encryptor?(password)
        encryptor_arguments = [
          encrypted_password,
          password,
          self.class.stretches,
          self.class.password_salt,
          self.class.pepper
        ]
        encryptor_class.compare(*encryptor_arguments)
      end

      def log_error(msg, error)
        try(:logger)&.error("#{msg}: #{error}")
      end

      def encryptor_class
        self.class.encryptor_class
      end

      # class method get injected into Devise module
      module ClassMethods
        Devise::Models.config(self, :encryptor, :override_existing_password_hash)

        # Returns the class for the configured encryptor.
        def encryptor_class
          @encryptor_class ||= compute_encryptor_class(encryptor)
        end

        def password_salt
          encryptor_class.salt(stretches)
        end

        private

        def compute_encryptor_class(encryptor)
          case encryptor
          when :bcrypt
            raise 'In order to use bcrypt as encryptor, simply remove :migratable from your devise model'
          when nil
            raise 'You need to give an :encryptor as option in order to use :migratable'
          else
            Devise::Migratable::Encryptors.const_get(encryptor.to_s.classify)
          end
        end
      end
    end
  end
end
