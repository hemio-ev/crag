module Network.ACME.Types where

import Crypto.JOSE ()
import Data.Aeson
import GHC.Generics
import Network.HTTP.Types
import Network.Socket (HostName)
import Network.URI

import Network.ACME.Internal

{-|
In order to help clients configure themselves with the right URIs for
each ACME operation, ACME servers provide a directory object.
-}
data AcmeDirectory = AcmeDirectory
  { acmeDirectory :: Maybe AcmeRequestDirectory
  , acmeDirectoryNewNonce :: Maybe AcmeRequestNewNonce
  , acmeDirectoryNewReg :: Maybe AcmeRequestNewReg
  , acmeDirectoryNewApp :: Maybe URI -- ^ New application
  , acmeDirectoryNewAuthz :: Maybe URI -- ^ New authorization
  , acmeDirectoryRevokeCert :: Maybe URI -- ^ Revoke certificate
  , acmeDirectoryKeyChange :: Maybe URI -- ^ Key change
  , acmeDirectoryMeta :: Maybe AcmeDirectoryMeta
  , acmeDirectoryNewCert :: Maybe URI -- ^ Boulder's non-standard field
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

-- | Request class
class Show a =>
      AcmeRequest a  where
  acmeRequestUrl :: a -> URI
  acmeRequestHttpMethod :: a -> StdMethod
  acmeRequestExpectedStatus :: a -> Status

-- | Directory
data AcmeRequestDirectory =
  AcmeRequestDirectory URI
  deriving (Show, Eq, Generic)

instance FromJSON AcmeRequestDirectory

instance AcmeRequest AcmeRequestDirectory where
  acmeRequestUrl (AcmeRequestDirectory u) = u
  acmeRequestHttpMethod = const GET
  acmeRequestExpectedStatus = const ok200

-- | New nonce
data AcmeRequestNewNonce =
  AcmeRequestNewNonce URI
  deriving (Show, Eq, Generic)

instance FromJSON AcmeRequestNewNonce

instance AcmeRequest AcmeRequestNewNonce where
  acmeRequestUrl (AcmeRequestNewNonce u) = u
  acmeRequestHttpMethod = const HEAD
  acmeRequestExpectedStatus = const ok200

-- | New registration
data AcmeRequestNewReg =
  AcmeRequestNewReg URI
  deriving (Show, Eq, Generic)

instance FromJSON AcmeRequestNewReg

instance AcmeRequest AcmeRequestNewReg where
  acmeRequestUrl (AcmeRequestNewReg u) = u
  acmeRequestHttpMethod = const POST
  acmeRequestExpectedStatus = const created201

