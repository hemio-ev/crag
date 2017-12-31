{-|

<https://datatracker.ietf.org/doc/draft-ietf-acme-acme/ ACME>
and
<https://github.com/letsencrypt/boulder/blob/release/docs/acme-divergences.md Boulder>
are both devitating from the JWS Standard.
This module provides the necessary tweaks to the JOSE library.

* Boulder only supports the
  <https://tools.ietf.org/html/rfc7515#page-21 "Flattened JWS JSON Serialization Syntax">.
  See also the
  <https://github.com/letsencrypt/boulder/issues/2532 issue against boulder>. 
  Therefore this module provides 'AcmeJws' that serializes to flattened jws.
* ACME uses an currently unregisterd header parameter "nonce".
  The 'AcmeJwsHeader' supports the required header parameters.
-}
module Network.ACME.JWS
  ( module Network.ACME.JWS
  , JWK
  , Base64Octets(..)
  ) where

import Control.Exception (throw)

--import Control.Lens       (Identity(..), Lens', view, review, set, (&), (?~), at)
import Control.Lens (Identity(..), review, set, view)
import Control.Monad.Except
import Crypto.JOSE
import Crypto.JOSE.Types (Base64Octets(..))
import Data.Aeson

import Control.Lens.TH (makeLenses)

--import Data.Aeson.Lens
import qualified Data.ByteString.Char8 as B
import Data.ByteString.Lazy (toStrict)

import Network.ACME.Errors
import Network.ACME.Object (AcmeJwsNonce, URL, urlToString)

type AcmeJws = FlattenedJWS AcmeJwsHeader

-- | Enhanced 'JWSHeader' with additional header parameters
data AcmeJwsHeader a = AcmeJwsHeader
  { _acmeJwsHeaderNonce :: AcmeJwsNonce
  , _acmeJwsHeaderUrl :: URL
  , _acmeJwsHeader :: JWSHeader a
  } deriving (Show)

makeLenses ''AcmeJwsHeader

instance HasParams AcmeJwsHeader where
  parseParamsFor proxy hp hu =
    AcmeJwsHeader <$> headerRequiredProtected "nonce" hp hu <*>
    headerRequiredProtected "url" hp hu <*>
    parseParamsFor proxy hp hu
  params h =
    (True, "nonce" .= view acmeJwsHeaderNonce h) :
    (True, "url" .= view acmeJwsHeaderUrl h) : params (view acmeJwsHeader h)
  extensions = const ["nonce", "url"]

instance HasJWSHeader AcmeJwsHeader where
  jwsHeader = acmeJwsHeader

newAcmeJwsHeader ::
     URL -- ^ Request URL
  -> JWK -- ^ Private key
  -> JWK -- ^ Public key
  -> AcmeJwsNonce -- ^ Nonce
  -> Maybe URL -- ^ Kid
  -> AcmeJwsHeader Protection
newAcmeJwsHeader vUrl vJwkPrivate vJwkPublic vNonce vKid
 -- Boulder sais
 -- 'detail: signature type 'PS512' in JWS header is not supported'
 =
  AcmeJwsHeader
  { _acmeJwsHeader = setAuth $ newJWSHeader (Protected, bestAlg)
  , _acmeJwsHeaderNonce = vNonce
  , _acmeJwsHeaderUrl = vUrl
  }
  where
    bestAlg =
      case bestJWSAlg vJwkPrivate of
        Right PS512 -> RS256
        Right x -> x
        Left e -> throw $ AcmeErrJws e
    setAuth =
      case vKid of
        Just k -> set kid (Just $ HeaderParam Protected (urlToString k))
        Nothing -> set jwk (Just $ HeaderParam Protected vJwkPublic)

-- | Removes private key
jwkPublic :: AsPublicKey a => a -> a
jwkPublic vJwk =
  case view asPublicKey vJwk of
    Nothing -> throw AcmeErrJwkNoPubkey
    Just k -> k

{-|
Creates a signed JWS object in ACME format. This implies interaction with the
ACME server for obtaining a valid nonce for this request.
-}
acmeNewJwsBody ::
     (ToJSON a)
  => a
  -> URL
  -> JWK
  -> JWK
  -> AcmeJwsNonce
  -> Maybe URL
  -> IO AcmeJws
acmeNewJwsBody vObj vUrl vJwkPrivate vJwkPublic vNonce vKid = do
  res <- runExceptT $ signJWS payload (Identity (vHeader, vJwkPrivate))
  case res of
    Left e -> throw $ AcmeErrJws e
    Right r -> return r
  where
    vHeader = newAcmeJwsHeader vUrl vJwkPrivate vJwkPublic vNonce vKid
    payload = toStrict $ encode vObj

-- | JSON Web Key (JWK) Thumbprint
-- <https://tools.ietf.org/html/rfc7638 RFC 7638>
jwkThumbprint :: JWK -> String
jwkThumbprint x =
  B.unpack $ review (base64url . digest) (view thumbprint x :: Digest SHA256)

sha256 :: String -> String
sha256 x =
  B.unpack $ review (base64url . digest) (hash (B.pack x) :: Digest SHA256)
