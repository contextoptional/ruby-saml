require File.expand_path(File.dirname(__FILE__) + '/incoming_message.rb')
require "xml_security"
require "time"

module Onelogin::Saml

  class Response
    include IncomingMessage
  end
end
