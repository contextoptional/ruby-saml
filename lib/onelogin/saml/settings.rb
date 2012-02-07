module Onelogin::Saml
  class Settings
    attr_accessor :assertion_consumer_service_url, :issuer, :sp_name_qualifier
    attr_accessor :idp_sso_target_url, :idp_cert_fingerprint, :idp_cert, :name_identifier_format, :idp_single_logout_target_url
	  attr_accessor :authn_context
    attr_accessor :private_key, :sp_cert
  end
end
