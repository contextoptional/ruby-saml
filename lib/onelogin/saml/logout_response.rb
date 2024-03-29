module Onelogin::Saml
  class LogoutResponse
    include OutgoingMessage
    include IncomingMessage

    def create(logout_request)
      self.request_doc = REXML::Document.new
      root = create_root_element(self.request_doc, "LogoutResponse")
      if settings.issuer != nil
        issuer = root.add_element "saml:Issuer", {"xmlns:saml" => ASSERTION}
        issuer.text = settings.issuer
      end
      root.attributes["InResponseTo"] = logout_request.id
      root.attributes["Destination"] = settings.idp_single_logout_target_url

      status_element = root.add_element "samlp:Status", {"xmlns:samlp" => PROTOCOL}
      status_code_element = status_element.add_element "samlp:StatusCode", {"xmlns:samlp" => PROTOCOL}
      status_code_element.attributes["Value"] = "urn:oasis:names:tc:SAML:2.0:status:Success"

      self
    end

    def parameter_name
      "SAMLResponse"
    end

    def url
      settings.idp_single_logout_target_url
    end
  end
end