# encoding: utf-8
# Copyright 2012 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

##
# Validates strings alleged to be ID Tokens issued by Google; if validation
#  succeeds, returns the decoded ID Token as a hash.
# It's a good idea to keep an instance of this class around for a long time,
#  because it caches the keys, performs validation statically, and only
#  refreshes from Google when required (once per day by default)
#
# @author Tim Bray, adapted from code by Bob Aman

require 'multi_json'
require 'jwt'
require 'openssl'
require 'net/http'

module GoogleIDToken
  class CertificateError < StandardError; end
  class ValidationError < StandardError; end
  class ExpiredTokenError < ValidationError; end
  class SignatureError < ValidationError; end
  class InvalidIssuerError < ValidationError; end
  class AudienceMismatchError < ValidationError; end

  class Validator

    GOOGLE_CERTS_URI = 'https://www.googleapis.com/oauth2/v1/certs'
    GOOGLE_CERTS_EXPIRY = 86400 # 1 day

    # https://developers.google.com/identity/sign-in/web/backend-auth
    GOOGLE_ISSUERS = ['accounts.google.com', 'https://accounts.google.com']

    def initialize(keyopts = {})
      if keyopts[:x509_cert]
        @certs_mode = :literal
        @certs = { :_ => keyopts[:x509_cert] }
      # elsif keyopts[:jwk_uri]  # TODO
      #   @certs_mode = :jwk
      #   @certs = {}
      else
        @certs_mode = :old_skool
        @certs = {}
      end

      @certs_expiry = keyopts.fetch(:expiry, GOOGLE_CERTS_EXPIRY)
    end

    ##
    # If it validates, returns a hash with the JWT payload from the ID Token.
    #  You have to provide an "aud" value, which must match the
    #  token's field with that name.
    #
    # If something fails, raises an error
    #
    # @param [String] token
    #   The string form of the token
    # @param [String] aud
    #   The required audience value
    # @param [String] cid
    #   Deprecated client-id ("azp" field) value (not verified)
    #
    # @return [Hash] The decoded ID token
    def check(token, aud, cid = nil)
      payload = check_cached_certs(token, aud)

      unless payload
        # no certs worked, might've expired, refresh
        if refresh_certs
          payload = check_cached_certs(token, aud)

          unless payload
            raise SignatureError, 'Token not verified as issued by Google'
          end
        else
          raise CertificateError, 'Unable to retrieve Google public keys'
        end
      end

      payload
    end

    private

    # tries to validate the token against each cached cert.
    # Returns the token payload or raises a ValidationError or
    #  nil, which means none of the certs validated.
    def check_cached_certs(token, aud)
      payload = nil

      # find first public key that validates this token
      @certs.detect do |key, cert|
        begin
          public_key = cert.public_key
          decoded_token = JWT.decode(token, public_key, !!public_key)
          payload = decoded_token.first
        rescue JWT::ExpiredSignature
          raise ExpiredTokenError, 'Token signature is expired'
        rescue JWT::DecodeError => e
          nil # go on, try the next cert
        end
      end

      if payload
        if !(payload.has_key?('aud') && payload['aud'] == aud)
          raise AudienceMismatchError, 'Token audience mismatch'
        end
        if !GOOGLE_ISSUERS.include?(payload['iss'])
          raise InvalidIssuerError, 'Token issuer mismatch'
        end
        payload
      else
        nil
      end
    end

    # returns false if there was a problem
    def refresh_certs
      case @certs_mode
      when :literal
        true # no-op
      when :old_skool
        old_skool_refresh_certs
      # when :jwk          # TODO
      #  jwk_refresh_certs
      end
    end

    def old_skool_refresh_certs
      return true unless certs_cache_expired?

      uri = URI(GOOGLE_CERTS_URI)
      get = Net::HTTP::Get.new uri.request_uri
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      res = http.request(get)

      if res.is_a?(Net::HTTPSuccess)
        new_certs = Hash[MultiJson.load(res.body).map do |key, cert|
                           [key, OpenSSL::X509::Certificate.new(cert)]
                         end]
        @certs.merge! new_certs
        @certs_last_refresh = Time.now
        true
      else
        false
      end
    end

    def certs_cache_expired?
      if defined? @certs_last_refresh
        Time.now > @certs_last_refresh + @certs_expiry
      else
        true
      end
    end
  end
end
