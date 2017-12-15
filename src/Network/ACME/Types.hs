module Network.ACME.Types where

import Crypto.JOSE (JWK)
import Crypto.JOSE.Types (Base64Octets)
import Data.Time (ZonedTime)
import qualified Network.HTTP.Client
import Network.Socket (HostName)
import Network.URI (URI)

import Network.ACME.Internal

-- * ACME Internal?
data AcmeState = AcmeState
  { acmeStateDirectory :: AcmeObjDirectory
  , acmeStateNonce :: Maybe AcmeJwsNonce
  , acmeStateJwkPrivate :: JWK
  , acmeStateJwkPublic :: JWK
  , acmeStateKid :: Maybe URL
  , acmeStateHttpManager :: Network.HTTP.Client.Manager
  }

type URL = URI

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
  { acmeDirectoryMetaTermsOfService :: Maybe URL
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
  , acmeObjStubAccountOnlyReturnExisting :: Maybe URI
  } deriving (Show)

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
data AcmeObjOrder = AcmeObjOrder
  { acmeObjOrderIdentifiers :: [AcmeObjIdentifier]
  , acmeObjOrderNotBefore :: Maybe ZonedTime
  , acmeObjOrderNotAfter :: Maybe ZonedTime
  } deriving (Show)

--acmeObjOrderCsr :: Base64Octets
data AcmeObjOrderStatus = AcmeObjOrderStatus
  { acmeObjOrderStatusAuthorizations :: [URL]
  , acmeObjOrderStatusNotBefore :: Maybe ZonedTime
  , acmeObjOrderStatusNotAfter :: Maybe ZonedTime
  , acmeObjOrderStatusIdentifiers :: [AcmeObjIdentifier]
  , acmeObjOrderStatusFinalize :: URL
  , acmeObjOrderStatusCertificate :: Maybe URL
  } deriving (Show)

data AcmeObjFinalize = AcmeObjFinalize
  { acmeObjFinalizeCsr :: Base64Octets
  } deriving (Show)

-- * ACME Certificate
data AcmeObjCertificateRevoke = AcmeObjCertificateRevoke
  { acmeObjCertificateRevokeCertificate :: Base64Octets
  , acmeObjCertificateRevokeReason :: Maybe Int
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

concat <$> mapM
  deriveAcmeJSON
  [ ''AcmeDirectoryMeta
  , ''AcmeJwsNonce
  , ''AcmeKeyAuthorization
  , ''AcmeObjAccount
  , ''AcmeObjAccountKeyRollover
  , ''AcmeObjAuthorization
  , ''AcmeObjCertificateRevoke
  , ''AcmeObjChallenge
  , ''AcmeObjChallengeResponse
  , ''AcmeObjDirectory
  , ''AcmeObjFinalize
  , ''AcmeObjIdentifier
  , ''AcmeObjNewAuthorization
  , ''AcmeObjOrder
  , ''AcmeObjOrderStatus
  , ''AcmeObjStubAccount
  , ''ProblemDetail
  ]
