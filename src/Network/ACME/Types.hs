module Network.ACME.Types where

import Crypto.JOSE (KeyMaterial)
import Crypto.JOSE.Types (Base64Octets)
import Data.Aeson
import Data.Time
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
  { acmeObjDirectory :: Maybe AcmeRequestDirectory
  , acmeObjDirectoryNewNonce :: Maybe AcmeRequestNewNonce
  , acmeObjDirectoryNewAccount :: Maybe AcmeRequestNewAccount
  , acmeObjDirectoryNewOrder :: Maybe AcmeRequestNewOrder
  , acmeObjDirectoryNewAuthz :: Maybe AcmeRequestNewAuthz
  , acmeObjDirectoryRevokeCert :: Maybe URI -- ^ Revoke certificate
  , acmeObjDirectoryKeyChange :: Maybe URI -- ^ Key change
  , acmeObjDirectoryMeta :: Maybe AcmeDirectoryMeta
  , acmeObjDirectoryNewCert :: Maybe AcmeRequestNewOrder -- ^ Boulder legacy
  , acmeObjDirectoryNewReg :: Maybe AcmeRequestNewAccount -- ^ Boulder legacy
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
  { acmeObjAccountKey :: KeyMaterial
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
newtype AcmeRequestNewAccount =
  AcmeRequestNewAccount URI
  deriving (Show, Generic)

instance FromJSON AcmeRequestNewAccount

instance AcmeRequest AcmeRequestNewAccount where
  acmeRequestUrl (AcmeRequestNewAccount u) = u
  acmeRequestExpectedStatus = const created201

-- ** Recover Account URI
newtype AcmeRequestAccountURI =
  AcmeRequestAccountURI URI
  deriving (Show, Generic)

instance AcmeRequest AcmeRequestAccountURI where
  acmeRequestUrl (AcmeRequestAccountURI u) = u
  acmeRequestExpectedStatus = const conflict409

-- ** Update Account
newtype AcmeRequestUpdateAccount =
  AcmeRequestUpdateAccount URI
  deriving (Show, Generic)

instance AcmeRequest AcmeRequestUpdateAccount where
  acmeRequestUrl (AcmeRequestUpdateAccount u) = u
  acmeRequestExpectedStatus = const accepted202

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
data AcmeObjNewAuthz = AcmeObjNewAuthz
  { acmeObjNewAuthzIdentifier :: AcmeObjIdentifier
  , acmeObjNewAuthzExisting :: Maybe String
  } deriving (Show, Generic)

instance ToJSON AcmeObjNewAuthz where
  toJSON = toAcmeRequestBody "acmeObjNewAuthz"

acmeNewDnsAuthz :: HostName -> AcmeObjNewAuthz
acmeNewDnsAuthz domain =
  AcmeObjNewAuthz
  { acmeObjNewAuthzIdentifier =
      AcmeObjIdentifier
      {acmeObjIdentifierType = "dns", acmeObjIdentifierValue = domain}
  , acmeObjNewAuthzExisting = Nothing
  }

-- | Create new authorization if none exists
newtype AcmeRequestNewAuthz =
  AcmeRequestNewAuthz URI
  deriving (Show, Generic)

instance FromJSON AcmeRequestNewAuthz

instance AcmeRequest AcmeRequestNewAuthz where
  acmeRequestUrl (AcmeRequestNewAuthz u) = u
  acmeRequestExpectedStatus = const created201

-- Existing Authorizations
-- | Get existing authorizations
newtype AcmeRequestExistingAuthz =
  AcmeRequestExistingAuthz URI
  deriving (Show, Generic)

instance AcmeRequest AcmeRequestExistingAuthz where
  acmeRequestUrl (AcmeRequestExistingAuthz u) = u
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
  acmeRequestExpectedStatus = const status202

-- * ACME Nonce
-- | Nonce
newtype AcmeJwsNonce =
  AcmeJwsNonce String
  deriving (Show, Generic)

instance ToJSON AcmeJwsNonce

newtype AcmeRequestNewNonce =
  AcmeRequestNewNonce URI
  deriving (Show, Generic)

instance FromJSON AcmeRequestNewNonce

instance AcmeRequest AcmeRequestNewNonce where
  acmeRequestUrl (AcmeRequestNewNonce u) = u
  acmeRequestExpectedStatus = const ok200

-- * ACME Application
-- ** New Application
-- | new-app
data AcmeObjOrder = AcmeObjOrder
  { acmeObjOrderCsr :: Base64Octets
  , acmeObjOrderNot_Before :: Maybe ZonedTime
  , acmeObjOrderNot_After :: Maybe ZonedTime
  } deriving (Show, Generic)

instance ToJSON AcmeObjOrder where
  toJSON = toAcmeRequestBody "acmeObjOrder"

newAcmeObjOrder :: Base64Octets -> AcmeObjOrder
newAcmeObjOrder xs =
  AcmeObjOrder
  { acmeObjOrderCsr = xs
  , acmeObjOrderNot_Before = Nothing
  , acmeObjOrderNot_After = Nothing
  }

-- | New application
newtype AcmeRequestNewOrder =
  AcmeRequestNewOrder URI
  deriving (Show, Generic)

instance FromJSON AcmeRequestNewOrder

instance AcmeRequest AcmeRequestNewOrder where
  acmeRequestUrl (AcmeRequestNewOrder u) = u
  acmeRequestExpectedStatus = const created201

-- * Misc
-- | Request class
class Show a =>
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
