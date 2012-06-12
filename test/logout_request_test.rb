require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class LogoutRequestTest < Test::Unit::TestCase
  context "LogoutRequest" do
    should "create a logout request" do
      settings = Onelogin::Saml::Settings.new
      settings.idp_single_logout_target_url = "http://logout"
      request_doc = Onelogin::Saml::LogoutRequest.new(settings).build_document("logout_name")
    end
  end

  context "LogoutResponse" do
    should "create a logout response" do
      settings = Onelogin::Saml::Settings.new
      settings.idp_single_logout_target_url = "http://logout"
      puts "Unparsed request: #{logout_request_document}"
      request = Onelogin::Saml::LogoutRequest.new(settings).parse(logout_request_document)
      puts "Logout Request: #{request.document.to_s}"
      response_document = Onelogin::Saml::LogoutResponse.new(settings).build_document(request)
      puts "Response document: #{response_document.to_s}"
    end
  end
end