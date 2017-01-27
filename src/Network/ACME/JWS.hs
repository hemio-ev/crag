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

import Crypto.JOSE
import Control.Lens (preview, makeLenses)
import Data.Monoid ((<>))
import GHC.Exts (fromList)
import Data.Maybe (fromJust)
import Control.Monad.Except

import Data.Aeson

-- | Enhanced 'JWSHeader' with additional header parameters
newtype AcmeJwsHeader = AcmeJwsHeader
  { _jwsStandardHeader :: JWSHeader
  } deriving (Show, Eq)

makeLenses ''AcmeJwsHeader

instance HasParams AcmeJwsHeader where
  params x =
    [ ( Protected
      , ( "nonce"
        , toJSON ("c3RbwD11NDfZpBoCkyPnFoQWeHrtNupY9_9N-LMUFe" :: String)))
    ] ++
    params (_jwsStandardHeader x)
  parseParamsFor = parseParamsFor

instance HasJWSHeader AcmeJwsHeader where
  jWSHeader = jwsStandardHeader

newAcmeJwsHeader
  :: JWK -- ^ Same key as used for signing. It's okay to include the private key.
  -> AcmeJwsHeader
newAcmeJwsHeader jwk =
  AcmeJwsHeader
    ((newJWSHeader (Unprotected, alg))
     { _jwsHeaderJwk = Just $ HeaderParam Unprotected jwkPublic
     })
  where
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
toJSONflat (JWS p [s]) = Object $ toObject s <> fromList ["payload" .= p]
  where
    toObject
      :: ToJSON a
      => a -> Object
    toObject a =
      case toJSON a of
        Object o -> o
        _ -> undefined
toJSONflat (JWS _ _) = undefined

signWith :: JWS AcmeJwsHeader -> KeyMaterial -> IO (JWS AcmeJwsHeader)
signWith jwsContent keyMat = do
  signed <- runExceptT $ signJWS jwsContent header' jwk
  return $
    case signed of
      Left e -> error $ show (e :: Error)
      Right jwsSign -> jwsSign
  where
    header' = newAcmeJwsHeader jwk
    jwk = fromKeyMaterial keyMat
