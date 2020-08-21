module Devise
    module Migratable
      module Encryptors
        # https://en.wikipedia.org/wiki/PBKDF2
        # Adapted from https://gitlab.com/gitlab-org/gitlab/-/blob/373f088e755f678478b8dd1627fab908d2641b21/vendor/gems/devise-pbkdf2-encryptable/lib/devise/pbkdf2_encryptable/encryptors/pbkdf2_sha512.rb
        class Pbkdf2Sha512 < Base
          STRATEGY = 'pbkdf2-sha512'
  
          # since stretches and iterations are part of the hashed pass, so ignore them during comparing
          def self.compare(encrypted_password, password, _stretches, _salt, pepper)
            split_digest = self.split_digest(encrypted_password)
            value_to_test = sha512_checksum(password, split_digest[:stretches], split_digest[:salt], pepper)
  
            Devise.secure_compare(split_digest[:checksum], value_to_test)
          end
  
          def self.digest(password, stretches, salt, pepper)
            checksum = sha512_checksum(password, stretches, salt, pepper)
  
            format_hash(STRATEGY, stretches, salt, checksum)
          end
  
          private_class_method def self.sha512_checksum(password, stretches, salt, pepper)
            hash = OpenSSL::Digest.new('SHA512')
            pbkdf2_checksum(hash, password, stretches, salt, pepper)
          end
  
          private_class_method def self.pbkdf2_checksum(hash, password, stretches, salt, pepper)
            OpenSSL::KDF.pbkdf2_hmac(
              password.to_s,
              salt: "#{[salt].pack('H*')}#{pepper}",
              iterations: stretches,
              hash: hash,
              length: hash.digest_length
            ).unpack1('H*')
          end
  
          # Passlib-style hash: $pbkdf2-sha512$rounds$salt$checksum
          # where salt and checksum are "adapted" Base64 encoded
          private_class_method def self.format_hash(strategy, stretches, salt, checksum)
            encoded_salt = passlib_encode64(salt)
            encoded_checksum = passlib_encode64(checksum)
  
            "$#{strategy}$#{stretches}$#{encoded_salt}$#{encoded_checksum}"
          end
  
          private_class_method def self.passlib_encode64(value)
            Base64.strict_encode64([value].pack('H*')).tr('+', '.').delete('=')
          end
  
          private_class_method def self.passlib_decode64(value)
            enc = value.tr('.', '+')
            Base64.decode64(enc).unpack1('H*')
          end
  
          private_class_method def self.split_digest(hash)
            split_digest = hash.split('$')
            _, strategy, stretches, salt, checksum = split_digest
  
            raise InvalidHash, 'invalid PBKDF2 hash' unless split_digest.length == 5 && strategy.start_with?('pbkdf2-')
  
            { strategy: strategy, stretches: stretches.to_i,
              salt: passlib_decode64(salt), checksum: passlib_decode64(checksum) }
          end
        end
      end
    end
  end
  