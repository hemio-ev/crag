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
  Therefore we provide 'toJSONflat'.
* ACME uses an currently unregisterd header parameter "nonce".
  The 'AcmeJwsHeader' supports the required header parameters.
-}
module Network.ACME.JWS where

import Control.Lens (preview, makeLenses, (&), (?~), at)
import Control.Monad.Except
import Crypto.JOSE
import Data.Aeson
import Data.Aeson.Lens
import Data.Maybe (fromJust)
import Network.URI (URI, pathSegments)
import Data.ByteString.Lazy (toStrict)

import Network.ACME.Types (AcmeJwsNonce)

-- | Enhanced 'JWSHeader' with additional header parameters
data AcmeJwsHeader = AcmeJwsHeader
  { _jwsStandardHeader :: JWSHeader
  , _jwsAcmeHeaderNonce :: AcmeJwsNonce
  } deriving (Show, Eq)

makeLenses ''AcmeJwsHeader

instance HasParams AcmeJwsHeader where
  params x =
    [(Protected, ("nonce", toJSON (_jwsAcmeHeaderNonce x)))] ++
    params (_jwsStandardHeader x)
  parseParamsFor = parseParamsFor

instance HasJWSHeader AcmeJwsHeader where
  jWSHeader = jwsStandardHeader

newAcmeJwsHeader
  :: JWK -- ^ Same key as used for signing. It's okay to include the private key.
  -> AcmeJwsNonce -- ^ Nonce
  -> AcmeJwsHeader
newAcmeJwsHeader jwk nonce =
  AcmeJwsHeader
  { _jwsStandardHeader = header'
  , _jwsAcmeHeaderNonce = nonce
  }
  where
    header' =
      (newJWSHeader (Unprotected, alg))
      { _jwsHeaderJwk = Just $ HeaderParam Unprotected jwkPublic
      }
    alg :: Alg
    alg =
      case bestJWSAlg jwk of
        Left e -> error (show (e :: Error))
        Right x -> x
    -- Removes private key
    jwkPublic :: JWK
    jwkPublic = fromJust $ preview asPublicKey jwk

-- | Generates JWS with /Flattened JWS JSON Serialization Syntax/
toJSONflat
  :: HasParams t
  => JWS t -> Value
toJSONflat (JWS p [s]) = toJSON s & _Object . at "payload" ?~ toJSON p
toJSONflat (JWS _ _) = undefined

jwsSigned
  :: (ToJSON a)
  => a
  -> URI
  -> KeyMaterial
  -> AcmeJwsNonce
  -> ExceptT Error IO (JWS AcmeJwsHeader)
jwsSigned payload url = signWith (newJWS $ toStrict $ encode payload')
  where
    payload' =
      toJSON payload & _Object . at "resource" ?~
      toJSON (last $ pathSegments url)

signWith
  :: JWS AcmeJwsHeader
  -> KeyMaterial
  -> AcmeJwsNonce
  -> ExceptT Error IO (JWS AcmeJwsHeader)
signWith jwsContent keyMat nonce = signJWS jwsContent header' jwk
  where
    header' = newAcmeJwsHeader jwk nonce
    jwk = fromKeyMaterial keyMat
