module Network.ACME.Types where

import Crypto.JOSE (KeyMaterial)
import Data.Aeson
import GHC.Generics
import Network.HTTP.Types
import Network.Socket (HostName)
import Network.URI
import Data.Time
import Crypto.JOSE.Types (Base64Octets)

import Network.ACME.Internal

-- * Abstractions
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

-- ** Recover Account URI
newtype AcmeRequestAccountURI =
  AcmeRequestAccountURI URI
  deriving (Show, Generic)

instance AcmeRequest AcmeRequestAccountURI where
  acmeRequestUrl (AcmeRequestAccountURI u) = u
  acmeRequestExpectedStatus = const conflict409

-- ** Account Update
newtype AcmeRequestUpdateAccount =
  AcmeRequestUpdateAccount URI
  deriving (Show, Generic)

instance AcmeRequest AcmeRequestUpdateAccount where
  acmeRequestUrl (AcmeRequestUpdateAccount u) = u
  acmeRequestExpectedStatus = const accepted202

-- * Requests and Returned Objects
-- | Request class
class Show a =>
      AcmeRequest a  where
  acmeRequestUrl :: a -> URI
  acmeRequestExpectedStatus :: a -> Status

-- ** Directory
{-|
In order to help clients configure themselves with the right URIs for
each ACME operation, ACME servers provide a directory object.
-}
data AcmeObjDirectory = AcmeObjDirectory
  { acmeObjDirectory :: Maybe AcmeRequestDirectory
  , acmeObjDirectoryNewNonce :: Maybe AcmeRequestNewNonce
  , acmeObjDirectoryNewAccount :: Maybe AcmeRequestNewAccount
  , acmeObjDirectoryNewOrder :: Maybe AcmeRequestNewOrder
  , acmeObjDirectoryNewAuthz :: Maybe URI -- ^ New authorization
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

-- ** New Nonce
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

-- ** New Account
-- | New account
newtype AcmeRequestNewAccount =
  AcmeRequestNewAccount URI
  deriving (Show, Generic)

instance FromJSON AcmeRequestNewAccount

instance AcmeRequest AcmeRequestNewAccount where
  acmeRequestUrl (AcmeRequestNewAccount u) = u
  acmeRequestExpectedStatus = const created201

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
