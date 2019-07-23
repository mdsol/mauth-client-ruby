module MAuth
  # mAuth client was unable to verify the authenticity of a signed object (this does NOT mean the
  # object is inauthentic). typically due to a failure communicating with the mAuth service, in
  # which case the error may include the attribute mauth_service_response - a response from
  # the mauth service (if it was contactable at all), which may contain more information about
  # the error.
  class UnableToAuthenticateError < StandardError
    # the response from the MAuth service encountered when attempting to retrieve authentication
    attr_accessor :mauth_service_response
  end

  # used to indicate that an object was expected to be validly signed but its signature does not
  # match its contents, and so is inauthentic.
  class InauthenticError < StandardError; end

  # Used when the incoming request does not contain any mAuth related information
  class MAuthNotPresent < StandardError; end

  # required information for signing was missing
  class UnableToSignError < StandardError; end

  # used when an object has the V1 headers but not the V2 headers and the
  # V2_ONLY_AUTHENTICATE variable is set to true.
  class MissingV2Error < StandardError; end

  class Client
    class ConfigurationError < StandardError; end
  end
end
