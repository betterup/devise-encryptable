require 'test_helper'
require 'benchmark'

class Pbkdf2Sha512Test < ActiveSupport::TestCase
  include Support::Assertions
  include Support::Factories
  include Support::Swappers

  STETCHES = 210_000
  PEPPER = 'thisisasuperlongstringusedontopofsalt'.freeze

  def encrypt_password(admin, pepper = Admin.pepper, stretches = Admin.stretches, encryptor = Admin.encryptor_class)
    encryptor.digest('123456', stretches, admin.password_salt, pepper)
  end

  def random_salt
    Devise::Migratable::Encryptors::Base.salt(STETCHES)
  end

  test 'digest and compare success' do
    plain_pass = 'password1'
    hashed_password = Devise::Migratable::Encryptors::Pbkdf2Sha512.digest(plain_pass, STETCHES, random_salt, PEPPER)
    assert Devise::Migratable::Encryptors::Pbkdf2Sha512.compare(hashed_password, plain_pass, nil, nil, PEPPER)
  end

  test 'invalid password hash raise' do
    plain_pass = 'password1'
    assert_raise(Devise::Migratable::Encryptors::InvalidHash) do
      Devise::Migratable::Encryptors::Pbkdf2Sha512.compare('wrongformatpasshash', plain_pass, nil, nil, PEPPER)
    end
  end

  test 'wrong password' do
    plain_pass = 'password1'
    hashed_password = Devise::Migratable::Encryptors::Pbkdf2Sha512.digest(plain_pass, 210_000, random_salt, PEPPER)
    refute Devise::Migratable::Encryptors::Pbkdf2Sha512.compare(hashed_password, 'wrongpass', nil, nil, PEPPER)
  end

  test 'changed pepper will fail password check' do
    plain_pass = 'password1'
    hashed_password = Devise::Migratable::Encryptors::Pbkdf2Sha512.digest(plain_pass, 210_000, random_salt, PEPPER)
    refute Devise::Migratable::Encryptors::Pbkdf2Sha512.compare(hashed_password, plain_pass, nil, nil,
                                                            'opps, different pepper')
  end
end
