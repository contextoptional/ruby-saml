require File.expand_path(File.dirname(__FILE__) + '/outgoing_message.rb')
require "base64"
require "uuid"
require "zlib"
require "cgi"
require "rexml/document"
require "rexml/xpath"

module Onelogin::Saml
  include REXML

  class Authrequest
    include OutgoingMessage

    def create(params = {})
      request_doc = REXML::Document.new
      root = create_root_element(request_doc, "AuthnRequest")

      # Conditionally defined elements based on settings
      if settings.assertion_consumer_service_url != nil
        root.attributes["AssertionConsumerServiceURL"] = settings.assertion_consumer_service_url
      end
      if settings.issuer != nil
        issuer = root.add_element "saml:Issuer", {"xmlns:saml" => ASSERTION}
        issuer.text = settings.issuer
      end
      if settings.name_identifier_format != nil
        root.add_element "samlp:NameIDPolicy", {
          "xmlns:samlp" => PROTOCOL,
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
          "xmlns:samlp" => PROTOCOL,
          "Comparison" => "exact",
        }
        class_ref = requested_context.add_element "saml:AuthnContextClassRef", {
          "xmlns:saml" => ASSERTION,
        }
        class_ref.text = settings.authn_context
      end

      sign_request(request_doc)

      encode_request(request_doc, params)
    end
  end
end
