module Network.ACME.Object
  ( module Network.ACME.Object
  , URL
  ) where

import Crypto.JOSE (JWK)
import Crypto.JOSE.Types (Base64Octets)
import Data.Default.Class (Default(def))
import Data.Time (ZonedTime)
import Network.Socket (HostName)
import Network.URI (URI, parseURI)

import Network.ACME.Internal

-- * Directory
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

-- * Account
-- | Account
data AcmeObjAccount = AcmeObjAccount
  { acmeObjAccountStatus :: String
  , acmeObjAccountContact :: Maybe [String]
  , acmeObjAccountTermsOfServiceAgreed :: Maybe Bool
  , acmeObjAccountOrders :: Maybe URI
  } deriving (Show)

-- ** New Account
-- | Stub account needed for account creation or inquire
data AcmeObjStubAccount = AcmeObjStubAccount
  { acmeObjStubAccountContact :: Maybe [String]
  , acmeObjStubAccountTermsOfServiceAgreed :: Maybe Bool
  , acmeObjStubAccountOnlyReturnExisting :: Maybe Bool
  } deriving (Show)

instance Default AcmeObjStubAccount where
  def = AcmeObjStubAccount Nothing Nothing Nothing

-- ** Account key roll-over
data AcmeObjAccountKeyRollover = AcmeObjAccountKeyRollover
  { acmeObjAccountKeyRolloverAccount :: URL
  , acmeObjAccountKeyRolloverNewKey :: JWK
  -- ^ New key
  } deriving (Show)

-- * Order
data AcmeObjOrder = AcmeObjOrder
  { acmeObjOrderStatus :: String
  , acmeObjOrderIdentifiers :: [AcmeObjIdentifier]
  , acmeObjOrderExpires :: Maybe ZonedTime
  , acmeObjOrderNotBefore :: Maybe ZonedTime
  , acmeObjOrderNotAfter :: Maybe ZonedTime
  , acmeObjOrderError :: Maybe ProblemDetail
  , acmeObjOrderAuthorizations :: [URL]
  , acmeObjOrderFinalize :: URL
  , acmeObjOrderCertificate :: Maybe URL
  } deriving (Show)

-- ** New Order
-- | new-order
data AcmeObjNewOrder = AcmeObjNewOrder
  { acmeObjNewOrderIdentifiers :: [AcmeObjIdentifier]
  , acmeObjNewOrderNotBefore :: Maybe ZonedTime
  , acmeObjNewOrderNotAfter :: Maybe ZonedTime
  } deriving (Show)

-- ** Identifier
-- | Identifier (original ACME standard only supports type /dns/)
data AcmeObjIdentifier = AcmeObjIdentifier
  { acmeObjIdentifierType :: String
  , acmeObjIdentifierValue :: String
  } deriving (Show)

-- ** Finalize Order
data AcmeObjFinalizeOrder = AcmeObjFinalizeOrder
  { acmeObjFinalizeOrderCsr :: Base64Octets
  } deriving (Show)

-- * Authorization
-- | Authorization
data AcmeObjAuthorization = AcmeObjAuthorization
  { acmeObjAuthorizationIdentifier :: AcmeObjIdentifier
  , acmeObjAuthorizationStatus :: String
  , acmeObjAuthorizationExpires :: Maybe ZonedTime
  , acmeObjAuthorizationScope :: Maybe URI
  , acmeObjAuthorizationChallenges :: [AcmeObjChallenge]
  } deriving (Show)

-- ** Challenge
data AcmeObjChallenge = AcmeObjChallenge
  { acmeObjChallengeType :: String
  , acmeObjChallengeUrl :: URL
  , acmeObjChallengeStatus :: String
  , acmeObjChallengeValidated :: Maybe ZonedTime
  , acmeObjChallengeErrors :: Maybe [ProblemDetail]
  , acmeObjChallengeToken :: String
  } deriving (Show)

-- ** Challenge Response
data AcmeObjChallengeResponse = AcmeObjChallengeResponse
  { acmeObjChallengeResponseKeyAuthorization :: AcmeKeyAuthorization
  } deriving (Show)

data AcmeKeyAuthorization =
  AcmeKeyAuthorization String
  deriving (Show)

-- * Nonce
-- | Nonce
newtype AcmeJwsNonce =
  AcmeJwsNonce String
  deriving (Show)

-- * Certificate Revokation
data AcmeObjRevokeCertificate = AcmeObjRevokeCertificate
  { acmeObjRevokeCertificateCertificate :: Base64Octets
  , acmeObjRevokeCertificateReason :: Maybe Int
  } deriving (Show)

-- * Problem Detail (Error)
-- | Problem Details for HTTP APIs
-- (<https://tools.ietf.org/html/rfc7807 RFC 7807>)
data ProblemDetail = ProblemDetail
  { problemDetailType :: Maybe URI
  , problemDetailTitle :: Maybe String
  , problemDetailStatus :: Maybe Int
  , problemDetailDetail :: Maybe String
  , problemDetailInstance :: Maybe URI
  } deriving (Show)

-- * URL
parseURL :: String -> Maybe URL
parseURL x = do
  u <- parseURI x
  if isValidURL u
    then return (URL u)
    else Nothing

urlToString :: URL -> String
urlToString (URL u) = show u

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
    , ''AcmeObjNewOrder
    , ''AcmeObjOrder
    , ''AcmeObjStubAccount
    , ''ProblemDetail
    ]
