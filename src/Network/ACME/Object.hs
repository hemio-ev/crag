module Network.ACME.Object
  ( URL
  , module Network.ACME.Object
  ) where

import Crypto.JOSE (JWK)
import Crypto.JOSE.Types (Base64Octets)
import Data.Default.Class (Default(def))
import Data.Time (ZonedTime)
import Network.Socket (HostName)
import Network.URI (URI, parseURI)

import Network.ACME.Internal

parseURL :: String -> Maybe URL
parseURL x = do
  u <- parseURI x
  if isValidURL u
    then return (URL u)
    else Nothing

urlToString :: URL -> String
urlToString (URL u) = show u

-- * ACME Directory
{-|
In order to help clients configure themselves with the right URIs for
each ACME operation, ACME servers provide a directory object.
-}
data AcmeObjDirectory = AcmeObjDirectory
  { acmeObjDirectoryNewNonce :: URL
  , acmeObjDirectoryNewAccount :: Maybe URL
  , acmeObjDirectoryNewOrder :: Maybe URL
  , acmeObjDirectoryNewAuthz :: Maybe URL
  , acmeObjDirectoryRevokeCert :: Maybe URL
  , acmeObjDirectoryKeyChange :: Maybe URL
  , acmeObjDirectoryMeta :: Maybe AcmeDirectoryMeta
  } deriving (Show)

{-|
Metadata relating to the service provided by the ACME server
-}
data AcmeDirectoryMeta = AcmeDirectoryMeta
  { acmeDirectoryMetaTermsOfService :: Maybe URI
  , acmeDirectoryMetaWebsite :: Maybe URL
  , acmeDirectoryMetaCaaIdentities :: Maybe [HostName]
  } deriving (Show)

-- | Directory
-- * ACME Accounts
-- | ACME account
data AcmeObjAccount = AcmeObjAccount
  { acmeObjAccountStatus :: String
  , acmeObjAccountContact :: Maybe [String]
  , acmeObjAccountTermsOfServiceAgreed :: Maybe Bool
  , acmeObjAccountOrders :: Maybe URI
  } deriving (Show)

data AcmeObjStubAccount = AcmeObjStubAccount
  { acmeObjStubAccountContact :: Maybe [String]
  , acmeObjStubAccountTermsOfServiceAgreed :: Maybe Bool
  , acmeObjStubAccountOnlyReturnExisting :: Maybe Bool
  } deriving (Show)

instance Default AcmeObjStubAccount where
  def = AcmeObjStubAccount Nothing Nothing Nothing

-- ** New Account
-- ** Retrive URI
-- ** Update
-- ** Key Rollover
data AcmeObjAccountKeyRollover = AcmeObjAccountKeyRollover
  { acmeObjAccountKeyRolloverNewKey :: JWK
  , acmeObjAccountKeyRolloverAccount :: Maybe URL
  } deriving (Show)

-- * ACME Authorization
-- | Authorization
data AcmeObjAuthorization = AcmeObjAuthorization
  { acmeObjAuthorizationIdentifier :: AcmeObjIdentifier
  , acmeObjAuthorizationStatus :: String
  , acmeObjAuthorizationExpires :: Maybe ZonedTime
  , acmeObjAuthorizationScope :: Maybe URI
  , acmeObjAuthorizationChallenges :: [AcmeObjChallenge]
  } deriving (Show)

-- | Authorization identifier (usually Domain)
data AcmeObjIdentifier = AcmeObjIdentifier
  { acmeObjIdentifierType :: String
  , acmeObjIdentifierValue :: String
  } deriving (Show)

-- ** New Authorizations
-- | New authorization
data AcmeObjNewAuthorization = AcmeObjNewAuthorization
  { acmeObjNewAuthorizationIdentifier :: AcmeObjIdentifier
  , acmeObjNewAuthorizationExisting :: Maybe String
  } deriving (Show)

acmeNewDnsAuthz :: HostName -> AcmeObjNewAuthorization
acmeNewDnsAuthz domain =
  AcmeObjNewAuthorization
  { acmeObjNewAuthorizationIdentifier =
      AcmeObjIdentifier
      {acmeObjIdentifierType = "dns", acmeObjIdentifierValue = domain}
  , acmeObjNewAuthorizationExisting = Nothing
  }

-- Existing Authorizations
-- * ACME Challenges
data AcmeObjChallenge = AcmeObjChallenge
  { acmeObjChallengeType :: String
  , acmeObjChallengeUrl :: URL
  , acmeObjChallengeStatus :: String
  , acmeObjChallengeValidated :: Maybe ZonedTime
  , acmeObjChallengeErrors :: Maybe [ProblemDetail]
  , acmeObjChallengeToken :: String
  } deriving (Show)

data AcmeObjChallengeResponse = AcmeObjChallengeResponse
  { acmeObjChallengeResponseKeyAuthorization :: AcmeKeyAuthorization
  } deriving (Show)

data AcmeKeyAuthorization =
  AcmeKeyAuthorization String
  deriving (Show)

-- * ACME Nonce
-- | Nonce
newtype AcmeJwsNonce =
  AcmeJwsNonce String
  deriving (Show)

-- * ACME Order
-- ** New order
-- | new-order
data AcmeObjNewOrder = AcmeObjNewOrder
  { acmeObjNewOrderIdentifiers :: [AcmeObjIdentifier]
  , acmeObjNewOrderNotBefore :: Maybe ZonedTime
  , acmeObjNewOrderNotAfter :: Maybe ZonedTime
  } deriving (Show)

data AcmeObjOrder = AcmeObjOrder
  { acmeObjOrderAuthorizations :: [URL]
  , acmeObjOrderNotBefore :: Maybe ZonedTime
  , acmeObjOrderNotAfter :: Maybe ZonedTime
  , acmeObjOrderIdentifiers :: [AcmeObjIdentifier]
  , acmeObjOrderFinalize :: URL
  , acmeObjOrderCertificate :: Maybe URL
  } deriving (Show)

data AcmeObjFinalizeOrder = AcmeObjFinalizeOrder
  { acmeObjFinalizeOrderCsr :: Base64Octets
  } deriving (Show)

-- * ACME Certificate
data AcmeObjRevokeCertificate = AcmeObjRevokeCertificate
  { acmeObjRevokeCertificateCertificate :: Base64Octets
  , acmeObjRevokeCertificateReason :: Maybe Int
  } deriving (Show)

-- | Problem Details for HTTP APIs
-- (<https://tools.ietf.org/html/rfc7807 RFC 7807>)
data ProblemDetail = ProblemDetail
  { problemDetailType :: Maybe URI
  , problemDetailTitle :: Maybe String
  , problemDetailStatus :: Maybe Int
  , problemDetailDetail :: Maybe String
  , problemDetailInstance :: Maybe URI
  } deriving (Show)

concat <$>
  mapM
  deriveAcmeJSON
  [ ''AcmeDirectoryMeta
  , ''AcmeJwsNonce
  , ''AcmeKeyAuthorization
  , ''AcmeObjAccount
  , ''AcmeObjAccountKeyRollover
  , ''AcmeObjAuthorization
  , ''AcmeObjRevokeCertificate
  , ''AcmeObjChallenge
  , ''AcmeObjChallengeResponse
  , ''AcmeObjDirectory
  , ''AcmeObjFinalizeOrder
  , ''AcmeObjIdentifier
  , ''AcmeObjNewAuthorization
  , ''AcmeObjNewOrder
  , ''AcmeObjOrder
  , ''AcmeObjStubAccount
  , ''ProblemDetail
  ]
