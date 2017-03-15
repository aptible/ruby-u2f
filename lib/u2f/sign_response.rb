module U2F
  class SignResponse
    attr_reader :key_handle, :client_data_json, :client_data
    attr_reader :signature_data_raw

    def initialize(key_handle, client_data_encoded, signature_data_encoded)
      unless key_handle.is_a?(String)
        fail AttestationDecodeError, 'Invalid keyHandle: Not a string'
      end
      @key_handle = key_handle

      begin
        unless client_data_encoded.is_a?(String)
          fail AttestationDecodeError, 'Not a string'
        end
        @client_data_json = ::U2F.urlsafe_decode64(client_data_encoded)
        @client_data = ClientData.load_from_json(client_data_json)
      rescue AttestationDecodeError => e
        raise AttestationDecodeError, "Invalid clientData: #{e.message}"
      end

      unless signature_data_encoded.is_a?(String)
        fail AttestationDecodeError, 'Invalid signatureData: Not a string'
      end
      @signature_data_raw = ::U2F.urlsafe_decode64(signature_data_encoded)
    end

    def self.load_from_json(json)
      from_hash(::JSON.parse(json))
    rescue JSON::ParserError => e
      raise AttestationDecodeError, "Invalid JSON: #{e.message}"
    end

    def self.from_hash(data)
      new(data['keyHandle'], data['clientData'], data['signatureData'])
    end

    ##
    # Counter value that the U2F token increments every time it performs an
    # authentication operation
    def counter
      signature_data_raw.byteslice(1, 4).unpack('N').first
    end

    ##
    # signature is to be verified using the public key obtained during
    # registration.
    def signature
      signature_data_raw.byteslice(5..-1)
    end

    # Bit 0 being set to 1 indicates that the user is present. A different value
    # of Bit 0, as well as Bits 1 through 7, are reserved for future use.
    USER_PRESENCE_MASK = 0b00000001

    ##
    # If user presence was verified
    def user_present?
      byte = signature_data_raw.byteslice(0).unpack('C').first
      byte & USER_PRESENCE_MASK == 1
    end

    ##
    # Verifies the response against an app id and the public key of the
    # registered device
    def verify(app_id, public_key_pem)
      data = [
        ::U2F::DIGEST.digest(app_id),
        signature_data_raw.byteslice(0, 5),
        ::U2F::DIGEST.digest(client_data_json)
      ].join

      public_key = OpenSSL::PKey.read(public_key_pem)

      begin
        public_key.verify(::U2F::DIGEST.new, signature, data)
      rescue OpenSSL::PKey::PKeyError
        false
      end
    end
  end
end
