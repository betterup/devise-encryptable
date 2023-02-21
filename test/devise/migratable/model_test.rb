require 'test_helper'
require 'active_model'
require 'bcrypt'

class MigratableTest < ActiveSupport::TestCase
  include Support::Assertions
  include Support::Factories

  def unconfig_user_model(mock_salt: true)
    Class.new do
      include ActiveModel::Serialization
      include ActiveModel::Model
      extend ActiveModel::Callbacks
      include ActiveModel::Validations::Callbacks
      extend Devise::Models
      # in order to call update_column

      define_model_callbacks :update, only: :after

      devise :database_authenticatable, :migratable

      attr_accessor :encrypted_password, :encrypted_password_migrate_to

      def initialize(encrypted_password: '')
        self.encrypted_password = encrypted_password
        super
      end

      # skip active record layer
      def update_column(name, value)
        send("#{name}=", value)
      end

      define_singleton_method(:password_salt) do
        mock_salt ? 'here we go' : super()
      end

      def new_record?
        false
      end

      def attributes
        { 'encrypted_password' => nil, 'encrypted_password_migrate_to' => nil }
      end
    end
  end

  def configed_user_model
    Class.new(unconfig_user_model) do
      devise :database_authenticatable, :migratable, encryptor: :pbkdf2_sha512
    end
  end

  def configed_user_model_with_encryptor(encryptor: nil)
    Class.new(unconfig_user_model) do
      devise :database_authenticatable, :migratable, encryptor: encryptor
    end
  end

  def random_password_salt_user_model
    Class.new(unconfig_user_model(mock_salt: false)) do
      devise :database_authenticatable, 
        :migratable, 
        encryptor: :pbkdf2_sha512,
        override_existing_password_hash: proc { |_user| true }
    end
  end

  def user_model_with_additional_except_list
    Class.new(configed_user_model) do
      attr_accessor :phone

      def serializable_hash(options = {})
        options = options.try(:dup) || {}
        options[:except] ||= %i[phone]
        super options
      end

      def attributes
        { 'encrypted_password' => nil, 'encrypted_password_migrate_to' => nil, 'phone' => nil }
      end
    end
  end

  def user_model_always_new_record
    Class.new(configed_user_model) do
      def new_record?
        true
      end
    end
  end

  def configed_user_model_with_enable_overrides(enabled: true, feature_class: nil)
    Class.new(unconfig_user_model) do
      devise :database_authenticatable,
             :migratable,
             encryptor: :pbkdf2_sha512,
             override_existing_password_hash: proc { |_user| feature_class ? feature_class.try(:active?) : enabled }
    end
  end

  def make_user_model_raise_error_when_updating_attribute
    user_class = configed_user_model
    Class.new(user_class) do
      def update_column(_name, _value)
        raise ActiveRecord::ActiveRecordError, 'Can not update attribute somehow'
      end
    end
  end

  def valid_pbkdf2_hash?(pass)
    Devise::Migratable::Encryptors::Pbkdf2Sha512.valid_hash?(pass)
  end

  def valid_bcrypt_hash?(pass)
    ::BCrypt::Password.valid_hash?(pass)
  end

  test 'should generate salt while setting password' do
    user = configed_user_model.new
    user.password = 'password'

    new_encrypted_pass = '$pbkdf2-sha512$1$Hr4A4Ag$CMvUhq6jnDgfYLtLGYlI30t5kDl/enxTd0ATWSuK2NmekdY9osewu3b4KEaAhygMipdeE.9fL0Ur56bnDpQkTQ'
    assert_equal user.encrypted_password_migrate_to, new_encrypted_pass

    store_old_encrypted_pass = user.encrypted_password
    assert user.valid_password?('password')

    # now let's creat a new user instance and validate against the old one
    another_user = configed_user_model.new(encrypted_password: store_old_encrypted_pass)
    assert another_user.valid_password?('password')
  end

  test 'should save new encrypted pass if not exists at the beginning' do
    user = configed_user_model.new
    user.password = 'password'
    # let's nil it
    user.encrypted_password_migrate_to = nil
    user.valid_password?('password')
    # here the new encrypted password should be present
    refute user.encrypted_password_migrate_to.nil?
  end

  test 'should not serialize the new encrypted password col' do
    user = configed_user_model_with_enable_overrides(enabled: true).new
    user.password = 'password'
    # convert it to json
    inspect_str = user.inspect
    refute inspect_str.include?('encrypted_password_migrate_to')
  end

  test 'migratable should respect parent model except list' do
    user = user_model_with_additional_except_list.new
    user.phone = 'xx-xx-xxxx'
    inspect_str = user.inspect
    refute inspect_str.include?('phone')
  end

  test 'migratable should not raise error when update_column failed' do
    user = make_user_model_raise_error_when_updating_attribute.new
    user.password = 'password'
    # nil the encrypted_password_migrate_to column so this will enforce we are calling the update_column
    user.encrypted_password_migrate_to = nil
    assert user.valid_password?('password')
  end

  test 'migratable should not update_column when new record' do
    user = user_model_always_new_record.new
    user.password = 'password'
    # let's nil it
    user.encrypted_password_migrate_to = nil
    user.valid_password?('password')
    # do not issue update_column call for new_record
    assert user.encrypted_password_migrate_to.nil?
  end

  test 'migratable should override existing encrypted_password column if feature enabled' do
    user = configed_user_model_with_enable_overrides(enabled: true).new
    user.password = 'password'
    assert user.encrypted_password_migrate_to.nil?
    assert user.valid_password?('password')
    assert valid_pbkdf2_hash?(user.encrypted_password)
  end

  test 'migratable should override existing encrypted_password column when doing validation' do
    feature_class = Class.new do
      define_singleton_method(:active?) do
        false
      end
    end
    user_model = configed_user_model_with_enable_overrides(feature_class: feature_class)
    user = user_model.new
    user.password = 'password'
    refute user.encrypted_password_migrate_to.nil?
    assert valid_bcrypt_hash?(user.encrypted_password)
    # enable feature
    feature_class.define_singleton_method(:active?) do
      true
    end
    assert user.valid_password?('password')
    assert valid_pbkdf2_hash?(user.encrypted_password)
  end

  test 'migratable module would require encrypted_password_migrate_to' do
    required_fields = Devise::Models::Migratable.required_fields(configed_user_model)
    assert required_fields.include?(:encrypted_password_migrate_to)
  end

  test 'migratable should raise if given bcrypt as encryptor' do
    user = configed_user_model_with_encryptor(encryptor: :bcrypt).new
    assert_raise { user.password = 'password' }
  end

  test 'migratable should raise if not given encryptor arg' do
    user = configed_user_model_with_encryptor(encryptor: nil).new
    assert_raise { user.password = 'password' }
  end

  test 'random salt will be used for hashing password' do
    user = random_password_salt_user_model.new
    user.password = 'password'
    encrypted_password_first = user.encrypted_password
    user.password = 'password'
    encrypted_password_second = user.encrypted_password
    assert valid_pbkdf2_hash?(encrypted_password_first)
    assert valid_pbkdf2_hash?(encrypted_password_second)
    assert encrypted_password_first != encrypted_password_second
  end
end
