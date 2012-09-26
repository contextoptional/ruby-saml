require "base64"
require "uuid"
require "zlib"
require "cgi"
require "rexml/document"
require "rexml/xpath"

module Onelogin::Saml
  include REXML

  class LogoutRequest
    include OutgoingMessage
    include IncomingMessage

=begin
<saml2p:LogoutRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
	ID="21B78E9C6C8ECF16F01E4A0F15AB2D46" IssueInstant="2010-04-28T21:36:11.230Z"
	Version="2.0">
	<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://dloomac.service-now.com
	</saml2:Issuer>
	<saml2:NameID xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
		Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
		NameQualifier="http://idp.ssocircle.com" SPNameQualifier="https://dloomac.service-now.com/navpage.do">
		david.loo@service-now.com</saml2:NameID>
	<saml2p:SessionIndex>s211b2f811485b2a1d2cc4db2b271933c286771104
	</saml2p:SessionIndex>
</saml2p:LogoutRequest>
=end

    def create(login_name)
      uuid = "_" + UUID.new.generate
      time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
      # Create AuthnRequest root element using REXML
      self.request_doc = REXML::Document.new

      root = self.request_doc.add_element "samlp:LogoutRequest", {"xmlns:samlp" => PROTOCOL}
      root.attributes['ID'] = uuid
      root.attributes['IssueInstant'] = time
      root.attributes['Version'] = "2.0"

      # Conditionally defined elements based on settings
      if settings.assertion_consumer_service_url != nil
        root.attributes["AssertionConsumerServiceURL"] = settings.assertion_consumer_service_url
      end
      if settings.issuer != nil
        issuer = root.add_element "saml:Issuer", {"xmlns:saml" => ASSERTION}
        issuer.text = settings.issuer
      end
      name_id = root.add_element "saml:NameID", {
        "xmlns:saml" => ASSERTION,
        "Format" => settings.name_identifier_format
      }
      name_id.add_text(login_name)
      self
    end

    def url
      settings.idp_single_logout_target_url
    end
  end
end