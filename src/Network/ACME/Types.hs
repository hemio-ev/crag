module Network.ACME.Types where

import Crypto.JOSE (KeyMaterial)
import Data.Aeson
import GHC.Generics
import Network.HTTP.Types
import Network.Socket (HostName)
import Network.URI
import Data.Time

import Network.ACME.Internal

-- * Abstractions
-- | ACME account
data AcmeAccount = AcmeAccount
  { acmeAccountKey :: KeyMaterial
  , acmeAccountContact :: [String]
  } deriving (Show, Eq, Generic)

instance FromJSON AcmeAccount where
  parseJSON = parseAcmeServerResponse "acmeAccount"

instance ToJSON AcmeAccount where
  toJSON = toAcmeConfigStore "acmeAccount"

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
data AcmeDirectory = AcmeDirectory
  { acmeDirectory :: Maybe AcmeRequestDirectory
  , acmeDirectoryNewNonce :: Maybe AcmeRequestNewNonce
  , acmeDirectoryNewReg :: Maybe AcmeRequestNewReg
  , acmeDirectoryNewApp :: Maybe AcmeRequestNewApp -- ^ New application
  , acmeDirectoryNewAuthz :: Maybe URI -- ^ New authorization
  , acmeDirectoryRevokeCert :: Maybe URI -- ^ Revoke certificate
  , acmeDirectoryKeyChange :: Maybe URI -- ^ Key change
  , acmeDirectoryMeta :: Maybe AcmeDirectoryMeta
  , acmeDirectoryNewCert :: Maybe AcmeRequestNewApp -- ^ Boulder's non-standard field
  } deriving (Show, Eq, Generic)

instance FromJSON AcmeDirectory where
  parseJSON = parseAcmeServerResponse "acmeDirectory"

{-|
Metadata relating to the service provided by the ACME server
-}
data AcmeDirectoryMeta = AcmeDirectoryMeta
  { acmeDirectoryMetaTermsOfService :: Maybe URI
  , acmeDirectoryMetaWebsite :: Maybe URI
  , acmeDirectoryCaaIdentities :: Maybe [HostName]
  } deriving (Show, Eq, Generic)

instance FromJSON AcmeDirectoryMeta where
  parseJSON = parseAcmeServerResponse "acmeDirectoryMeta"

-- | Directory
newtype AcmeRequestDirectory =
  AcmeRequestDirectory URI
  deriving (Show, Eq, Generic)

instance FromJSON AcmeRequestDirectory

instance AcmeRequest AcmeRequestDirectory where
  acmeRequestUrl (AcmeRequestDirectory u) = u
  acmeRequestExpectedStatus = const ok200

-- ** New Nonce
-- | Nonce
newtype AcmeJwsNonce =
  AcmeJwsNonce String
  deriving (Show, Eq, Generic)

instance ToJSON AcmeJwsNonce

newtype AcmeRequestNewNonce =
  AcmeRequestNewNonce URI
  deriving (Show, Eq, Generic)

instance FromJSON AcmeRequestNewNonce

instance AcmeRequest AcmeRequestNewNonce where
  acmeRequestUrl (AcmeRequestNewNonce u) = u
  acmeRequestExpectedStatus = const ok200

-- ** New Registration
-- | new-reg
data AcmeObjNewReg = AcmeObjNewReg
  { acmeObjNewRegContact :: [String]
  } deriving (Show, Generic)

instance ToJSON AcmeObjNewReg where
  toJSON = toAcmeRequestBody "acmeObjNewReg"

-- | New registration
newtype AcmeRequestNewReg =
  AcmeRequestNewReg URI
  deriving (Show, Eq, Generic)

instance FromJSON AcmeRequestNewReg

instance AcmeRequest AcmeRequestNewReg where
  acmeRequestUrl (AcmeRequestNewReg u) = u
  acmeRequestExpectedStatus = const created201

-- ** New Application
-- | new-app
data AcmeObjNewApp = AcmeObjNewApp
  { acmeObjNewAppCsr :: String
  , acmeObjNewAppNot_Before :: Maybe ZonedTime
  , acmeObjNewAppNot_After :: Maybe ZonedTime
  } deriving (Show, Generic)

instance ToJSON AcmeObjNewApp where
  toJSON = toAcmeRequestBody "acmeObjNewApp"

newAcmeObjNewApp :: String -> AcmeObjNewApp
newAcmeObjNewApp xs =
  AcmeObjNewApp
  { acmeObjNewAppCsr = xs
  , acmeObjNewAppNot_Before = Nothing
  , acmeObjNewAppNot_After = Nothing
  }

-- | New application
newtype AcmeRequestNewApp =
  AcmeRequestNewApp URI
  deriving (Show, Eq, Generic)

instance FromJSON AcmeRequestNewApp

instance AcmeRequest AcmeRequestNewApp where
  acmeRequestUrl (AcmeRequestNewApp u) = u
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
  } deriving (Show, Eq, Generic)

instance FromJSON ProblemDetail where
  parseJSON = parseAcmeServerResponse "problemDetail"
