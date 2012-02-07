require File.expand_path(File.dirname(__FILE__) + '/saml_request.rb')
require "base64"
require "uuid"
require "zlib"
require "cgi"
require "rexml/document"
require "rexml/xpath"

module Onelogin::Saml
include REXML
  class Authrequest < SamlRequest
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

    encode_request(request_doc, settings, params)
    end

    
  end
end
