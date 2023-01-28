require 'test_helper'
require 'benchmark'

class PBKDF2Test < ActiveSupport::TestCase
  include Support::Assertions
  include Support::Factories
  include Support::Swappers

  STETCHES = 210_000
  PEPPER = 'thisisasuperlongstringusedontopofsalt'.freeze

  def encrypt_password(admin, pepper = Admin.pepper, stretches = Admin.stretches, encryptor = Admin.encryptor_class)
    encryptor.digest('123456', stretches, admin.password_salt, pepper)
  end

  def random_salt
    Devise::Encryptable::Encryptors::Base.salt(STETCHES)
  end

  test 'digest and compare success' do
    plain_pass = 'password1'
    hashed_password = Devise::Encryptable::Encryptors::Pbkdf2.digest(plain_pass, STETCHES, random_salt, PEPPER)
    assert Devise::Encryptable::Encryptors::Pbkdf2.compare(hashed_password, plain_pass, nil, nil, PEPPER)
  end

  test 'invalid password hash raise' do
    plain_pass = 'password1'
    assert_raise(Devise::Encryptable::Encryptors::InvalidHash) do
      Devise::Encryptable::Encryptors::Pbkdf2.compare('wrongformatpasshash', plain_pass, nil, nil, PEPPER)
    end
  end

  test 'wrong password' do
    plain_pass = 'password1'
    hashed_password = Devise::Encryptable::Encryptors::Pbkdf2.digest(plain_pass, 210_000, random_salt, PEPPER)
    assert !Devise::Encryptable::Encryptors::Pbkdf2.compare(hashed_password, 'wrongpass', nil, nil, PEPPER)
  end

  test 'changed pepper will fail password check' do
    plain_pass = 'password1'
    hashed_password = Devise::Encryptable::Encryptors::Pbkdf2.digest(plain_pass, 210_000, random_salt, PEPPER)
    assert !Devise::Encryptable::Encryptors::Pbkdf2.compare(hashed_password, plain_pass, nil, nil,
                                                            'opps, different pepper')
  end

  test 'devise using Pbkdf2' do
    swap_with_encryptor Admin, :Pbkdf2 do
      admin = create_admin
      assert_equal admin.encrypted_password,
                   encrypt_password(admin, Admin.pepper, Admin.stretches, Devise::Encryptable::Encryptors::Pbkdf2)
    end
  end

  test 'devise can compare using Pbkdf2' do
    swap_with_encryptor Admin, :Pbkdf2 do
      plain_pass = 'password1'
      admin = create_admin(password: plain_pass)
      assert admin.valid_password?(plain_pass)
    end
  end
end
