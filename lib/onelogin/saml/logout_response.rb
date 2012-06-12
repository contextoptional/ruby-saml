module Onelogin::Saml
  class LogoutResponse
    include OutgoingMessage
    include IncomingMessage

    def create(login_name, params = {})
      doc = build_document(login_name)

      encode_request(doc, params)
    end

    def build_document(logout_request, params = {})
      request_doc = REXML::Document.new
      root = create_root_element(request_doc, "LogoutResponse")
      root.attributes["InResponseTo"] = logout_request.id
      root.attributes["Destination"] = settings.idp_single_logout_target_url

      status_element = root.add_element "samlp:Status", {"xmlns:samlp" => PROTOCOL}
      status_code_element = status_element.add_element "samlp:StatusCode", {"xmlns:samlp" => PROTOCOL}
      status_code_element.attributes["Value"] = "urn:oasis:names:tc:SAML:2.0:status:Success"

      request_doc
    end

    def url
      settings.idp_single_logout_target_url
    end
  end
end