require "base64"
require "uuid"
require "zlib"
require "cgi"
require "rexml/document"
require "rexml/xpath"

module Onelogin::Saml
include REXML
  class Authrequest
    def create(settings, params = {})
		 	
      uuid = "_" + UUID.new.generate
      time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
		# Create AuthnRequest root element using REXML 
		request_doc = REXML::Document.new
		
		root = request_doc.add_element "samlp:AuthnRequest", { "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol" }
		root.attributes['ID'] = uuid
		root.attributes['IssueInstant'] = time
		root.attributes['Version'] = "2.0"
		
		# Conditionally defined elements based on settings
		if settings.assertion_consumer_service_url != nil
			root.attributes["AssertionConsumerServiceURL"] = settings.assertion_consumer_service_url
		end
		if settings.issuer != nil
			issuer = root.add_element "saml:Issuer", { "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" }
			issuer.text = settings.issuer
		end
		if settings.name_identifier_format != nil
			root.add_element "samlp:NameIDPolicy", { 
					"xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
					# Might want to make AllowCreate a setting?
					"AllowCreate" => "true",
					"Format" => settings.name_identifier_format
			}
		end
		
		# BUG fix here -- if an authn_context is defined, add the tags with an "exact"
		# match required for authentication to succeed.  If this is not defined, 
		# the IdP will choose default rules for authentication.  (Shibboleth IdP)
		if settings.authn_context != nil
			requested_context = root.add_element "samlp:RequestedAuthnContext", { 
				"xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
				"Comparison" => "exact",
			}
			class_ref = requested_context.add_element "saml:AuthnContextClassRef", { 
				"xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion",
			}			
			class_ref.text = settings.authn_context
		end
		
    sign_request(request_doc, settings)
      
		request = ""
		request_doc.write(request)
		
		Logging.debug "Created AuthnRequest: #{request}"
		
      deflated_request  = Zlib::Deflate.deflate(request, 9)[2..-5]
      base64_request    = Base64.encode64(deflated_request)
      encoded_request   = CGI.escape(base64_request)
      params_prefix     = (settings.idp_sso_target_url =~ /\?/) ? '&' : '?'
      request_params    = "#{params_prefix}SAMLRequest=#{encoded_request}"

      params.each_pair do |key, value|
        request_params << "&#{key}=#{CGI.escape(value.to_s)}"
      end

      settings.idp_sso_target_url + request_params
    end
    
    def sign_request(request_doc, settings)
      return unless settings.private_key
      
      xml_canonicalizer = XML::Util::XmlCanonicalizer.new(true,true)
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
  end
end
