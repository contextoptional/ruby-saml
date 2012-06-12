module Onelogin::Saml
  module IncomingMessage
    ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
    PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
    DSIG      = "http://www.w3.org/2000/09/xmldsig#"
    XENC      = "http://www.w3.org/2001/04/xmlenc#"

    attr_accessor :options, :response, :document, :settings

    def initialize(my_settings)
      raise ArgumentError.new("Settings cannot be nil") if my_settings.nil?
      self.settings = my_settings
    end

    def parse(response, options = {})
      raise ArgumentError.new("Response cannot be nil") if response.nil?
      self.options = options
      self.response = response
      self.document = XMLSecurity::SignedDocument.new(Base64.decode64(response))
      self
    end

    def id
      self.document.root.attributes["ID"]
    end

    def decrypt_assertions
      return unless settings.private_key

      @original_document ||= XMLSecurity::SignedDocument.new(self.document.to_s)
      Logging.debug("Response value: #{self.document.to_s}")
      key_cipher_value = REXML::XPath.first(self.document, "/p:Response/a:EncryptedAssertion/xenc:EncryptedData/dsig:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue", {"p" => PROTOCOL, "a" => ASSERTION, "xenc" => XENC, "dsig" => DSIG})
      return unless key_cipher_value
      private_key = OpenSSL::PKey::RSA.new(settings.private_key)
      key = private_key.private_decrypt(Base64.decode64(key_cipher_value.text))
      cipher_value = REXML::XPath.first(document, "/p:Response/a:EncryptedAssertion/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue", {"p" => PROTOCOL, "a" => ASSERTION, "xenc" => XENC, "dsig" => DSIG})
      return unless cipher_value
      cipher_value_text = Base64.decode64(cipher_value.text)
      cipher = OpenSSL::Cipher::Cipher.new('aes-128-cbc')
      cipher.decrypt
      cipher.key = key
      cipher.iv = cipher_value_text[0..16]
      assertion_text = cipher.update(cipher_value_text[16..-1])
      assertion_text << cipher.update("\x00" * 16)
      padding = assertion_text.bytes.to_a.last
      assertion_text = assertion_text[0..-(padding + 1)]
      Logging.debug("Assertion text: #{assertion_text}")
      assertion_element = REXML::Document.new(assertion_text)
      self.document.root.add_element(assertion_element.root)
    end

  # Conditions (if any) for the assertion to run
    def conditions
      @conditions ||= begin
        REXML::XPath.first(document, "/p:Response/a:Assertion[@ID='#{document.signed_element_id[1, document.signed_element_id.size]}']/a:Conditions", {"p" => PROTOCOL, "a" => ASSERTION})
      end
    end

  # When this user session should expire at latest
    def session_expires_at
      @expires_at ||= begin
        node = REXML::XPath.first(document, "/p:Response/a:Assertion/a:AuthnStatement", {"p" => PROTOCOL, "a" => ASSERTION})
        parse_time(node, "SessionNotOnOrAfter")
      end
    end

    def status_message
      @status_message ||= begin
        node = REXML::XPath.first(document, "/p:Response/p:Status/p:StatusMessage", {"p" => PROTOCOL})
        node && node.text
      end
    end

  # A hash of all the attributes with the response. Assuming there is only one value for each key
    def attributes
      @attr_statements ||= begin
        result = {}

        stmt_element = REXML::XPath.first(document, "/p:Response/a:Assertion/a:AttributeStatement", {"p" => PROTOCOL, "a" => ASSERTION})
        return {} if stmt_element.nil?

        stmt_element.elements.each do |attr_element|
          name = attr_element.attributes["Name"]
          value = attr_element.elements.first.text

          result[name] = value
        end

        result.keys.each do |key|
          result[key.intern] = result[key]
        end

        result
      end
    end

  # The value of the user identifier as designated by the initialization request response
    def name_id
      @name_id ||= begin
        node = REXML::XPath.first(document, "/p:Response/a:Assertion[@ID='#{document.signed_element_id[1, document.signed_element_id.size]}']/a:Subject/a:NameID", {"p" => PROTOCOL, "a" => ASSERTION})
        node ||= REXML::XPath.first(document, "/p:Response[@ID='#{document.signed_element_id[1, document.signed_element_id.size]}']/a:Assertion/a:Subject/a:NameID", {"p" => PROTOCOL, "a" => ASSERTION})
        node.nil? ? nil : node.text
      end
    end

    def validate!
      validate(soft = false)
    end

    def is_valid?
      validate(soft = true)
    end


    private

    def parse_time(node, attribute)
      if node && node.attributes[attribute]
        Time.parse(node.attributes[attribute])
      end
    end

    def validate_conditions(soft = true)
      return true if conditions.nil?
      return true if options[:skip_conditions]

      if not_before = parse_time(conditions, "NotBefore")
        if Time.now.utc < not_before
          return soft ? false : validation_error("Current time is earlier than NotBefore condition")
        end
      end

      if not_on_or_after = parse_time(conditions, "NotOnOrAfter")
        if Time.now.utc >= not_on_or_after
          return soft ? false : validation_error("Current time is on or after NotOnOrAfter condition")
        end
      end

      true
    end

    def get_fingerprint
      if settings.idp_cert
        cert = OpenSSL::X509::Certificate.new(settings.idp_cert)
        Digest::SHA1.hexdigest(cert.to_der).upcase.scan(/../).join(":")
      else
        settings.idp_cert_fingerprint
      end
    end

    def validate_response_state(soft = true)
      if response.empty?
        return soft ? false : validation_error("Blank response")
      end

      if settings.nil?
        return soft ? false : validation_error("No settings on response")
      end

      if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil?
        return soft ? false : validation_error("No fingerprint or certificate on settings")
      end

      true
    end

    def validate(soft = true)
      validate_response_state(soft) &&
        validate_conditions(soft) &&
        (@original_document || document).validate(get_fingerprint, soft)
    end

    def validation_error(message)
      raise ValidationError.new(message)
    end
  end
end