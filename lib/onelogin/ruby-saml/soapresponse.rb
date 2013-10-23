module Onelogin
  module Saml
    class SoapResponse < Response
      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
      DSIG      = "http://www.w3.org/2000/09/xmldsig#"
      SOAP      = "http://schemas.xmlsoap.org/soap/envelope/"
      
      attr_accessor :settings

      attr_reader :options
      attr_reader :response
      attr_reader :document


      def initialize
        raise ArgumentError.new("Response cannot be nil") if response.nil?
        envelope = REXML::Document.new(response)
        wrapped = REXML::XPath.first(envelope,'o:Envelope/o:Body/p:Response', {'p' => PROTOCOL, 'o' => SOAP})
        self.document = XMLSecurity::SignedDocument.new(wrapped.to_s)
      end
    end
  end
end