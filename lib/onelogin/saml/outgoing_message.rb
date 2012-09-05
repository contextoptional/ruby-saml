require "rexml/document"
require "rexml/xpath"

module Onelogin::Saml
  include REXML
  module OutgoingMessage
    ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
    PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
    DSIG      = "http://www.w3.org/2000/09/xmldsig#"
    XENC      = "http://www.w3.org/2001/04/xmlenc#"

    attr_accessor :settings

    def initialize(my_settings)
      raise ArgumentError.new("Settings cannot be nil") if my_settings.nil?
      self.settings = my_settings
    end

    protected
    def create_root_element(request_doc, element_name)
      uuid = "_" + UUID.new.generate
      time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
      # Create AuthnRequest root element using REXML

      root = request_doc.add_element "samlp:#{element_name}", {"xmlns:samlp" => PROTOCOL}
      root.attributes['ID'] = uuid
      root.attributes['IssueInstant'] = time
      root.attributes['Version'] = "2.0"
      root
    end

    def sign_request(request_doc)
      return unless settings.private_key

      xml_canonicalizer = XML::Util::XmlCanonicalizer.new(true, true)
      canonicalized_xml = xml_canonicalizer.canonicalize(request_doc)

      Logging.debug("Canonicalized XML: #{canonicalized_xml}")

      private_key = OpenSSL::PKey::RSA.new(settings.private_key)
      digest = OpenSSL::Digest::SHA256.new
      signature = Base64.encode64(private_key.sign(digest, canonicalized_xml))
      root = request_doc.root
      signature_element = root.add_element("ds:Signature", {"xmlns:ds" => "http://www.w3.org/2000/09/xmldsig#"})
      signed_info = signature_element.add_element("ds:SignedInfo", {"xmlns:ds" => "http://www.w3.org/2000/09/xmldsig#"})
      signed_info.add_element "ds:CanonicalizationMethod", {"xmlns:ds" => "http://www.w3.org/2000/09/xmldsig#", "Algorithm" => "http://www.w3.org/2001/10/xml-exc-c14n#"}
      signed_info.add_element "ds:SignatureMethod", {"xmlns:ds" => "http://www.w3.org/2000/09/xmldsig#", "Algorithm" => "http://www.w3.org/2000/09/xmldsig#rsa-sha1"}
      reference = signed_info.add_element("ds:Reference")
      transforms = reference.add_element("ds:Transforms")
      transforms.add_element("ds:Transform", {"Algorithm" => "http://www.w3.org/2000/09/xmldsig#enveloped-signature"})
      transform = transforms.add_element("ds:Transform", {"Algorithm" => "http://www.w3.org/2001/10/xml-exc-c14n#"})
      transform.add_element("ec:InclusiveNamespaces", {"xmlns:ec" => "http://www.w3.org/2001/10/xml-exc-c14n#", "PrefixList" => "ds saml samlp"})
      reference.add_element("ds:DigestMethod")
      digest_value = reference.add_element("ds:DigestValue")
      digest_value.add_text(digest.to_s)
      signature_value = signature_element.add_element("ds:SignatureValue")
      signature_value.add_text(signature)

      return unless settings.sp_cert
      x509_certificate = signature_element.add_element("ds:KeyInfo").add_element("ds:X509Data").add_element("ds:X509Certificate")
      x509_certificate.add_text(Base64.encode64(settings.sp_cert.to_s))

      Logging.debug("Signed Request Doc: #{request_doc.to_s}")
    end

    def encode_request(request_doc, params = {})
      request = ""
      request_doc.write(request)

      Logging.debug "Created AuthnRequest: #{request}"

      deflated_request = Zlib::Deflate.deflate(request, 9)[2..-5]
      base64_request = Base64.encode64(deflated_request)
      encoded_request = CGI.escape(base64_request)
      params_prefix = (self.url =~ /\?/) ? '&' : '?'
      request_params = "#{params_prefix}#{parameter_name}=#{encoded_request}"

      params.each_pair do |key, value|
        request_params << "&#{key}=#{CGI.escape(value.to_s)}"
      end

      self.url + request_params
    end

    def parameter_name
      "SAMLRequest"
    end

    def url
      settings.idp_sso_target_url
    end
  end
end
