module Network.ACME.Error where

import Crypto.JOSE
import qualified Data.ByteString.Lazy.Char8 as L

import Network.ACME.Object
import Network.HTTP.Client
import Network.HTTP.Types

type JwsError = Error

errBadNonce :: AcmeErr -> Bool
errBadNonce AcmeErrDetail {acmeErrProblemDetail = d}
  | (show <$> problemDetailType d) == Just "urn:ietf:params:acme:error:badNonce" =
    True
  | otherwise = False
errBadNonce _ = False

data AcmeErr
  -- | Server reported an error with structured details
  = AcmeErrDetail { acmeErrRequest :: URL
                  , acmeErrHttpStatus :: Status
                  , acmeErrProblemDetail :: ProblemDetail
                  , acmeErrRequestBody :: Maybe L.ByteString }
  -- | Wrapper for JWS Errors
  | AcmeErrJws JwsError
  | AcmeErrJwkNoPubkey
  -- | Wrapper for catched HTTP exceptions
  | AcmeErrHTTPS HttpException
  -- | Wanted challenge type to available
  | AcmeErrNoChallenge String
  | AcmeErrNoFullfillableChallenge { acmeErrNoFullfillableChallengeTypesSupported :: [String]
                                   , acmeErrNoFullfillableChallengeAuthorization :: AcmeObjAuthorization }
  -- | Challenge did not contain a "token" field
  | AcmeErrNoToken AcmeObjChallenge
  -- | Request not supported by the server (not in 'AcmeObjDirectory')
  | AcmeErrRequestNotSupported AcmeDirectoryRequest
  --
  -- API violations: The following errors should not occur
  --
  -- | Expected HTTP status but body has not the expected format
  | AcmeErrDecodingBody { acmeErrMessage :: String
                        , acmeErrBody :: String }
  | ErrDecodingPEM String
  -- | Unexpected HTTP response status, but response is not a 'ProblemDetail'
  | AcmeErrDecodingProblemDetail { acmeErrHttpStatus :: Status
                                 , acmeErrMessage :: String
                                 , acmeErrResponseBody :: String }
  -- | Header content could not be decoded
  | AcmeErrDecodingHeader { acmeErrHeaderName :: String
                          , acmeErrHeaderValue :: String }
  -- | Certificate could not be decoded
  | AcmeErrDecodingX509 { acmeErrMessage :: String
                        , acmeErrBody :: String }
  -- | Expected HTTP header not found
  | AcmeErrHeaderNotFound HeaderName
  deriving (Show)

data AcmeDirectoryRequest
  = AcmeDirectoryRequestRevokeCert
  | AcmeDirectoryRequestNewOrder
  | AcmeDirectoryRequestNewAuthz
  | AcmeDirectoryRequestNewAccount
  | AcmeDirectoryRequestKeyChange
  deriving (Show)

acmeRequestUrl :: AcmeDirectoryRequest -> (AcmeObjDirectory -> Maybe URL)
acmeRequestUrl AcmeDirectoryRequestRevokeCert = acmeObjDirectoryRevokeCert
acmeRequestUrl AcmeDirectoryRequestNewOrder = acmeObjDirectoryNewOrder
acmeRequestUrl AcmeDirectoryRequestNewAuthz = acmeObjDirectoryNewAuthz
acmeRequestUrl AcmeDirectoryRequestNewAccount = acmeObjDirectoryNewAccount
acmeRequestUrl AcmeDirectoryRequestKeyChange = acmeObjDirectoryKeyChange
