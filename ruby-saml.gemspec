# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run 'rake gemspec'
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "ruby-saml"
  s.version = "1.0.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["OneLogin LLC"]
  s.date = "2012-06-12"
  s.description = "SAML toolkit for Ruby on Rails"
  s.email = "support@onelogin.com"
  s.extra_rdoc_files = [
    "LICENSE",
    "README.rdoc"
  ]
  s.files = [
    ".document",
    "LICENSE",
    "README.rdoc",
    "Rakefile",
    "VERSION",
    "lib/onelogin/saml.rb",
    "lib/onelogin/saml/authrequest.rb",
    "lib/onelogin/saml/incoming_message.rb",
    "lib/onelogin/saml/logging.rb",
    "lib/onelogin/saml/logout_request.rb",
    "lib/onelogin/saml/logout_response.rb",
    "lib/onelogin/saml/metadata.rb",
    "lib/onelogin/saml/outgoing_message.rb",
    "lib/onelogin/saml/response.rb",
    "lib/onelogin/saml/settings.rb",
    "lib/onelogin/saml/validation_error.rb",
    "lib/ruby-saml.rb",
    "lib/xml_security.rb",
    "ruby-saml.gemspec",
    "test/certificates/certificate1",
    "test/logout_request_test.rb",
    "test/request_test.rb",
    "test/requests/logout_request.xml.base64",
    "test/response_test.rb",
    "test/responses/adfs_response.xml.base64",
    "test/responses/open_saml_response.xml",
    "test/responses/response1.xml.base64",
    "test/responses/response2.xml.base64",
    "test/responses/response3.xml.base64",
    "test/responses/response4.xml.base64",
    "test/responses/response5.xml.base64",
    "test/responses/simple_saml_php.xml",
    "test/settings_test.rb",
    "test/test_helper.rb",
    "test/xml_security_test.rb"
  ]
  s.homepage = "http://github.com/onelogin/ruby-saml"
  s.require_paths = ["lib"]
  s.rubygems_version = "1.8.24"
  s.summary = "SAML Ruby Tookit"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<canonix>, ["~> 0.1"])
      s.add_runtime_dependency(%q<uuid>, ["~> 2.3"])
      s.add_development_dependency(%q<shoulda>, [">= 0"])
      s.add_development_dependency(%q<mocha>, [">= 0"])
    else
      s.add_dependency(%q<canonix>, ["~> 0.1"])
      s.add_dependency(%q<uuid>, ["~> 2.3"])
      s.add_dependency(%q<shoulda>, [">= 0"])
      s.add_dependency(%q<mocha>, [">= 0"])
    end
  else
    s.add_dependency(%q<canonix>, ["~> 0.1"])
    s.add_dependency(%q<uuid>, ["~> 2.3"])
    s.add_dependency(%q<shoulda>, [">= 0"])
    s.add_dependency(%q<mocha>, [">= 0"])
  end
end

