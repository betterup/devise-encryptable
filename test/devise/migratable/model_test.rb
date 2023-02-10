require 'test_helper'
require 'active_model'

class MigratableTest < ActiveSupport::TestCase
  include Support::Assertions
  include Support::Factories

  def unconfig_user_model
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
      def update_column(_name, value)
        self.encrypted_password_migrate_to = value
      end

      # prevent moving salt everytime
      def self.password_salt
        'here we go'
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

  def random_password_salt_user_model
    Class.new(configed_user_model) do
      def self.password_salt
        Devise.friendly_token[0, 20]
      end
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

  def configed_user_model_with_feature(enabled: true)
    Class.new(unconfig_user_model) do
      devise :database_authenticatable,
             :migratable,
             encryptor: :pbkdf2_sha512,
             enable_validation: proc { |_user| enabled }
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

  test 'should validate against the new password column' do
    user = configed_user_model_with_feature(enabled: true).new
    user.password = 'password'
    # mess around with old one so we ensure it's checking against the new one
    user.encrypted_password = 'thisonly changes old one'
    assert user.valid_password?('password')
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

  test "should not save new encrypted password if it's already exists" do
    user = random_password_salt_user_model.new
    user.password = 'password'
    # check
    user.encrypted_password_migrate_to = nil
    assert user.valid_password?('password')
    # now it's set the new one
    new_encrypted_pass = user.encrypted_password_migrate_to
    # check validation again
    assert user.valid_password?('password')
    # new encrypted pass should not be updated if it's exists
    assert_equal new_encrypted_pass, user.encrypted_password_migrate_to
  end

  test 'should not serialize the new encrypted password col' do
    user = configed_user_model_with_feature(enabled: true).new
    user.password = 'password'
    # convert it to json
    inspect_str = user.inspect
    refute inspect_str.include?('encrypted_password_migrate_to')
  end

  test 'should not validate new encrypted password if feature flag is off' do
    user = configed_user_model_with_feature(enabled: false).new
    user.password = 'password'
    # manually set the encrypted_password_migrate_to to a wrong one
    user.encrypted_password_migrate_to = 'notrightone'
    assert user.valid_password?('password')
  end

  test 'should fallback to validating encrypted_password if encrypted_password_migrate_to not present even with feature enabled' do
    user = configed_user_model_with_feature(enabled: true).new
    user.password = 'password'
    # manually set the encrypted_password_migrate_to to empty
    user.encrypted_password_migrate_to = nil
    assert user.valid_password?('password')
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
end
