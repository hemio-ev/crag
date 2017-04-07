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

import Control.Lens
       (Identity(..), Lens', view, review, set, (&), (?~), at)
import Control.Monad.Trans.Except
import Crypto.JOSE
import Crypto.JOSE.Types (Base64Octets(..))
import Data.Aeson
import Data.Aeson.Lens
import qualified Data.ByteString.Char8 as B
import Data.ByteString.Lazy (toStrict)
import Network.URI (URI, pathSegments)

import Network.ACME.Errors
import Network.ACME.Types (AcmeJwsNonce)

type AcmeJws = FlattenedJWS AcmeJwsHeader

-- | Enhanced 'JWSHeader' with additional header parameters
data AcmeJwsHeader a = AcmeJwsHeader
  { _acmeJwsHeader :: JWSHeader a
  , _acmeJwsHeaderNonce :: AcmeJwsNonce
  } deriving (Show)

acmeJwsHeader :: Lens' (AcmeJwsHeader p) (JWSHeader p)
acmeJwsHeader f s@AcmeJwsHeader {_acmeJwsHeader = x} =
  fmap (\x' -> s {_acmeJwsHeader = x'}) (f x)

acmeJwsHeaderNonce :: Lens' (AcmeJwsHeader p) AcmeJwsNonce
acmeJwsHeaderNonce f s@AcmeJwsHeader {_acmeJwsHeaderNonce = x} =
  fmap (\x' -> s {_acmeJwsHeaderNonce = x'}) (f x)

instance HasParams AcmeJwsHeader where
  parseParamsFor proxy hp hu =
    AcmeJwsHeader <$> parseParamsFor proxy hp hu <*>
    headerRequiredProtected "nonce" hp hu
  params h =
    (True, "nonce" .= view acmeJwsHeaderNonce h) : params (view acmeJwsHeader h)
  extensions = const ["nonce"]

instance HasJWSHeader AcmeJwsHeader where
  jwsHeader = acmeJwsHeader

newAcmeJwsHeader
  :: JWK -- ^ Same key as used for signing. It's okay to include the private key.
  -> AcmeJwsNonce -- ^ Nonce
  -> Either JwsError (AcmeJwsHeader Protection)
newAcmeJwsHeader jwk' nonce
 -- Boulder sais
 -- 'detail: signature type 'PS512' in JWS header is not supported'
 = do
  alg' <-
    case bestJWSAlg jwk' of
      Right PS512 -> Right RS256
      x -> x
  let h =
        set
          jwk
          (HeaderParam Unprotected <$> jwkPublic jwk')
          (newJWSHeader (Unprotected, alg'))
  return AcmeJwsHeader {_acmeJwsHeader = h, _acmeJwsHeaderNonce = nonce}

-- | Removes private key
jwkPublic
  :: AsPublicKey a
  => a -> Maybe a
jwkPublic = view asPublicKey

jwsSigned
  :: (ToJSON a)
  => a -> URI -> JWK -> AcmeJwsNonce -> ExceptT JwsError IO AcmeJws
jwsSigned payload url = signWith payload'
    -- Workaround for old ACME draft
  where
    payload' =
      toStrict $ encode $ toJSON payload & _Object . at "resource" ?~
      toJSON (pathSegments url !! 1)

signWith :: B.ByteString -> JWK -> AcmeJwsNonce -> ExceptT JwsError IO AcmeJws
signWith jwsContent jwk' nonce =
  either throwE (\h -> signJWS jwsContent (Identity (h, jwk'))) header'
  where
    header' = newAcmeJwsHeader jwk' nonce

-- | JSON Web Key (JWK) Thumbprint
-- <https://tools.ietf.org/html/rfc7638 RFC 7638>
jwkThumbprint :: JWK -> String
jwkThumbprint x =
  B.unpack $ review (base64url . digest) (view thumbprint x :: Digest SHA256)

sha256 :: String -> String
sha256 x =
  B.unpack $ review (base64url . digest) (hash (B.pack x) :: Digest SHA256)
