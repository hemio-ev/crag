module Network.ACME.Type where

import Crypto.JOSE (JWK)
import Network.HTTP.Client (Manager)

import Network.ACME.Object

data AcmeState = AcmeState
  { acmeStateDirectory :: AcmeObjDirectory
  , acmeStateNonce :: Maybe AcmeJwsNonce
  , acmeStateJwkPrivate :: JWK
  , acmeStateJwkPublic :: JWK
  , acmeStateKid :: Maybe URL
  , acmeStateHttpManager :: Manager
  }
