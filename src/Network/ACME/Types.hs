module Network.ACME.Types where

import Crypto.JOSE (JWK)
import Crypto.JOSE.Types (Base64Octets)
import Data.Aeson
import Data.Time
import Data.Typeable
import GHC.Generics
import Network.HTTP.Types
import Network.Socket (HostName)
import Network.URI

import Network.ACME.Internal

-- * ACME Directory
{-|
In order to help clients configure themselves with the right URIs for
each ACME operation, ACME servers provide a directory object.
-}
data AcmeObjDirectory = AcmeObjDirectory
  { acmeObjDirectory :: Maybe AcmeRequestDirectory -- ^ Boulder workaround (new-nonce)
  , acmeObjDirectoryNewNonce :: Maybe AcmeRequestNonceNew
  , acmeObjDirectoryNewAccount :: Maybe AcmeRequestAccountNew
  , acmeObjDirectoryNewOrder :: Maybe AcmeRequestOrderNew
  , acmeObjDirectoryNewAuthz :: Maybe AcmeRequestAuthorziationNew
  , acmeObjDirectoryRevokeCert :: Maybe AcmeRequestCertificateRevoke
  , acmeObjDirectoryKeyChange :: Maybe AcmeRequestAccountKeyRollover
  , acmeObjDirectoryMeta :: Maybe AcmeDirectoryMeta
  , acmeObjDirectoryNewCert :: Maybe AcmeRequestOrderNew -- ^ Boulder legacy
  , acmeObjDirectoryNewReg :: Maybe AcmeRequestAccountNew -- ^ Boulder legacy
  } deriving (Show, Generic)

instance FromJSON AcmeObjDirectory where
  parseJSON = parseAcmeServerResponse "acmeObjDirectory"

{-|
Metadata relating to the service provided by the ACME server
-}
data AcmeDirectoryMeta = AcmeDirectoryMeta
  { acmeDirectoryMetaTermsOfService :: Maybe URI
  , acmeDirectoryMetaWebsite :: Maybe URI
  , acmeDirectoryCaaIdentities :: Maybe [HostName]
  } deriving (Show, Generic)

instance FromJSON AcmeDirectoryMeta where
  parseJSON = parseAcmeServerResponse "acmeDirectoryMeta"

-- | Directory
newtype AcmeRequestDirectory =
  AcmeRequestDirectory URI
  deriving (Show, Generic)

instance FromJSON AcmeRequestDirectory

instance AcmeRequest AcmeRequestDirectory where
  acmeRequestUrl (AcmeRequestDirectory u) = u
  acmeRequestExpectedStatus = const ok200

-- * ACME Accounts
-- | ACME account
data AcmeObjAccount = AcmeObjAccount
  { acmeObjAccountKey :: JWK
  , acmeObjAccountContact :: Maybe [String]
  , acmeObjAccountStatus :: Maybe String
  , acmeObjAccountTermsOfServiceAgreed :: Maybe Bool
  , acmeObjAccountOrders :: Maybe URI
  , acmeObjAccountAgreement :: Maybe URI -- ^ Boulder legacy
  } deriving (Show, Generic)

instance FromJSON AcmeObjAccount where
  parseJSON = parseAcmeServerResponse "acmeObjAccount"

instance ToJSON AcmeObjAccount where
  toJSON = toAcmeConfigStore "acmeObjAccount"

-- ** New Account
-- | New account
newtype AcmeRequestAccountNew =
  AcmeRequestAccountNew URI
  deriving (Show, Generic)

instance FromJSON AcmeRequestAccountNew

instance AcmeRequest AcmeRequestAccountNew where
  acmeRequestUrl (AcmeRequestAccountNew u) = u
  acmeRequestExpectedStatus = const created201

-- ** Retrive URI
newtype AcmeRequestAccountURI =
  AcmeRequestAccountURI URI
  deriving (Show, Generic)

instance AcmeRequest AcmeRequestAccountURI where
  acmeRequestUrl (AcmeRequestAccountURI u) = u
  acmeRequestExpectedStatus = const conflict409

-- ** Update
newtype AcmeRequestAccountUpdate =
  AcmeRequestAccountUpdate URI
  deriving (Show, Generic)

instance ToJSON AcmeRequestAccountUpdate

instance AcmeRequest AcmeRequestAccountUpdate where
  acmeRequestUrl (AcmeRequestAccountUpdate u) = u
  acmeRequestExpectedStatus = const accepted202

-- ** Key Rollover
data AcmeObjAccountKeyRollover = AcmeObjAccountKeyRollover
  { acmeObjAccountKeyRolloverNew_Key :: JWK
  , acmeObjAccountKeyRolloverAccount :: AcmeRequestAccountUpdate
  } deriving (Show, Generic)

instance ToJSON AcmeObjAccountKeyRollover where
  toJSON = toAcmeRequestBody "acmeObjAccountKeyRollover"

newtype AcmeRequestAccountKeyRollover =
  AcmeRequestAccountKeyRollover URI
  deriving (Show, Generic)

instance FromJSON AcmeRequestAccountKeyRollover

instance AcmeRequest AcmeRequestAccountKeyRollover where
  acmeRequestUrl (AcmeRequestAccountKeyRollover u) = u
  acmeRequestExpectedStatus = const ok200

-- * ACME Authorization
-- | Authorization
data AcmeObjAuthorization = AcmeObjAuthorization
  { acmeObjAuthorizationIdentifier :: AcmeObjIdentifier
  , acmeObjAuthorizationStatus :: String
  , acmeObjAuthorizationExpires :: Maybe ZonedTime
  , acmeObjAuthorizationScope :: Maybe URI
  , acmeObjAuthorizationChallenges :: [AcmeObjChallenge]
  } deriving (Show, Generic)

instance FromJSON AcmeObjAuthorization where
  parseJSON = parseAcmeServerResponse "acmeObjAuthorization"

-- | Authorization identifier (usually Domain)
data AcmeObjIdentifier = AcmeObjIdentifier
  { acmeObjIdentifierType :: String
  , acmeObjIdentifierValue :: String
  } deriving (Show, Generic)

instance FromJSON AcmeObjIdentifier where
  parseJSON = parseAcmeServerResponse "acmeObjIdentifier"

instance ToJSON AcmeObjIdentifier where
  toJSON = toAcmeRequestBody "acmeObjIdentifier"

-- ** New Authorizations
-- | New authorization
data AcmeObjAuthorizationNew = AcmeObjAuthorizationNew
  { acmeObjNewAuthzIdentifier :: AcmeObjIdentifier
  , acmeObjNewAuthzExisting :: Maybe String
  } deriving (Show, Generic)

instance ToJSON AcmeObjAuthorizationNew where
  toJSON = toAcmeRequestBody "acmeObjNewAuthz"

acmeNewDnsAuthz :: HostName -> AcmeObjAuthorizationNew
acmeNewDnsAuthz domain =
  AcmeObjAuthorizationNew
  { acmeObjNewAuthzIdentifier =
      AcmeObjIdentifier
      {acmeObjIdentifierType = "dns", acmeObjIdentifierValue = domain}
  , acmeObjNewAuthzExisting = Nothing
  }

-- | Create new authorization if none exists
newtype AcmeRequestAuthorziationNew =
  AcmeRequestAuthorziationNew URI
  deriving (Show, Generic)

instance FromJSON AcmeRequestAuthorziationNew

instance AcmeRequest AcmeRequestAuthorziationNew where
  acmeRequestUrl (AcmeRequestAuthorziationNew u) = u
  acmeRequestExpectedStatus = const created201

-- Existing Authorizations
-- | Get existing authorizations
newtype AcmeRequestAuthorizationExisting =
  AcmeRequestAuthorizationExisting URI
  deriving (Show, Generic)

instance AcmeRequest AcmeRequestAuthorizationExisting where
  acmeRequestUrl (AcmeRequestAuthorizationExisting u) = u
  acmeRequestExpectedStatus = const seeOther303

-- * ACME Challenges
data AcmeObjChallenge = AcmeObjChallenge
  { acmeObjChallengeType :: String
  , acmeObjChallengeUri :: AcmeRequestChallengeResponse -- ^ Boulder legacy, should be Url
  , acmeObjChallengeStatus :: String
  , acmeObjChallengeValidated :: Maybe ZonedTime
  , acmeObjChallengeError :: Maybe ProblemDetail
  , acmeObjChallengeToken :: Maybe String
  , acmeObjChallengeKey_Authorization :: Maybe String
  } deriving (Show, Generic)

--instance ToJSON AcmeObjChallenge
instance FromJSON AcmeObjChallenge where
  parseJSON = parseAcmeServerResponse "acmeObjChallenge"

data AcmeObjChallengeResponse = AcmeObjChallengeResponse
  { acmeObjChallengeResponseKey_Authorization :: String
  } deriving (Show, Generic)

instance ToJSON AcmeObjChallengeResponse where
  toJSON = toAcmeRequestBody "acmeObjChallengeResponse"

-- | Respond to a challenge
newtype AcmeRequestChallengeResponse =
  AcmeRequestChallengeResponse URI
  deriving (Show, Generic)

instance ToJSON AcmeRequestChallengeResponse

instance FromJSON AcmeRequestChallengeResponse

instance AcmeRequest AcmeRequestChallengeResponse where
  acmeRequestUrl (AcmeRequestChallengeResponse u) = u
  -- Boulder legacy: should be 200
  acmeRequestExpectedStatus = const accepted202

-- * ACME Nonce
-- | Nonce
newtype AcmeJwsNonce =
  AcmeJwsNonce String
  deriving (Show, Generic)

instance ToJSON AcmeJwsNonce

newtype AcmeRequestNonceNew =
  AcmeRequestNonceNew URI
  deriving (Show, Generic)

instance FromJSON AcmeRequestNonceNew

instance AcmeRequest AcmeRequestNonceNew where
  acmeRequestUrl (AcmeRequestNonceNew u) = u
  acmeRequestExpectedStatus = const ok200

-- * ACME Order
-- ** New order
-- | new-order
data AcmeObjOrder = AcmeObjOrder
  { acmeObjOrderCsr :: Base64Octets
  , acmeObjOrderNot_Before :: Maybe ZonedTime
  , acmeObjOrderNot_After :: Maybe ZonedTime
  } deriving (Show, Generic)

instance ToJSON AcmeObjOrder where
  toJSON = toAcmeRequestBody "acmeObjOrder"

-- | New order
newtype AcmeRequestOrderNew =
  AcmeRequestOrderNew URI
  deriving (Show, Generic)

instance FromJSON AcmeRequestOrderNew

instance AcmeRequest AcmeRequestOrderNew where
  acmeRequestUrl (AcmeRequestOrderNew u) = u
  acmeRequestExpectedStatus = const created201

-- * ACME Certificate
data AcmeObjCertificateRevoke = AcmeObjCertificateRevoke
  { acmeObjCertificateRevokeCertificate :: Base64Octets
  , acmeObjCertificateRevokeReason :: Maybe Int
  } deriving (Show, Generic)

instance ToJSON AcmeObjCertificateRevoke where
  toJSON = toAcmeRequestBody "acmeObjCertificateRevoke"

newtype AcmeRequestCertificateRevoke =
  AcmeRequestCertificateRevoke URI
  deriving (Show, Generic)

instance FromJSON AcmeRequestCertificateRevoke

instance AcmeRequest AcmeRequestCertificateRevoke where
  acmeRequestUrl (AcmeRequestCertificateRevoke u) = u
  acmeRequestExpectedStatus = const ok200

-- * Misc
-- | Request class
class (Show a, Typeable a) =>
      AcmeRequest a where
  acmeRequestUrl :: a -> URI
  acmeRequestExpectedStatus :: a -> Status

-- | Problem Details for HTTP APIs
-- (<https://tools.ietf.org/html/rfc7807 RFC 7807>)
data ProblemDetail = ProblemDetail
  { problemDetailType :: Maybe URI
  , problemDetailTitle :: Maybe String
  , problemDetailStatus :: Maybe Int
  , problemDetailDetail :: Maybe String
  , problemDetailInstance :: Maybe URI
  } deriving (Show, Generic)

instance FromJSON ProblemDetail where
  parseJSON = parseAcmeServerResponse "problemDetail"

instance ToJSON ProblemDetail where
  toJSON = toAcmeRequestBody "problemDetail"
