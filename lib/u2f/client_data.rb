# frozen_string_literal: true

module U2F
  ##
  # A representation of ClientData, chapter 7
  # http://fidoalliance.org/specs/fido-u2f-raw-message-formats-v1.0-rd-20141008.pdf
  class ClientData
    REGISTRATION_TYP   = 'navigator.id.finishEnrollment'
    AUTHENTICATION_TYP = 'navigator.id.getAssertion'

    attr_accessor :typ, :challenge, :origin
    alias type typ

    def initialize(typ, challenge, origin)
      @typ = typ
      @challenge = challenge
      @origin = origin

      %i(typ challenge origin).each do |sym|
        val = send(sym)
        next if val.is_a?(String)
        fail AttestationDecodeError, "Invalid #{sym}"
      end
    end

    def registration?
      typ == REGISTRATION_TYP
    end

    def authentication?
      typ == AUTHENTICATION_TYP
    end

    def self.load_from_json(json)
      from_hash(::JSON.parse(json))
      rescue JSON::ParserError => e

      raise AttestationDecodeError, "Invalid JSON: #{e.message}"
    end

    def self.from_hash(data)
      new(data['typ'], data['challenge'], data['origin'])
    end
  end
end
