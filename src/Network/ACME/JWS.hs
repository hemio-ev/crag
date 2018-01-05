{-|
JWS 
-}
module Network.ACME.JWS
  ( module Network.ACME.JWS
  , JWK
  , Base64Octets(..)
  ) where

import Control.Lens (Identity(..), review, set, view)
import Control.Lens.TH (makeLenses)
import Control.Monad.Except
import Crypto.JOSE
import Crypto.JOSE.Types (Base64Octets(..))
import Data.Aeson
import qualified Data.ByteString.Char8 as B
import Data.ByteString.Lazy (toStrict)

import Network.ACME.Error
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
  -> Either AcmeErr (AcmeJwsHeader Protection)
newAcmeJwsHeader vUrl vJwkPrivate vJwkPublic vNonce vKid
 -- Boulder sais
 -- 'detail: signature type 'PS512' in JWS header is not supported'
 = do
  vBestAlg <- bestAlg
  return
    AcmeJwsHeader
      { _acmeJwsHeader = setAuth $ newJWSHeader (Protected, vBestAlg)
      , _acmeJwsHeaderNonce = vNonce
      , _acmeJwsHeaderUrl = vUrl
      }
  where
    bestAlg =
      case bestJWSAlg vJwkPrivate of
        Right PS512 -> return RS256
        Right x -> return x
        Left e -> throwError $ AcmeErrJws e
    setAuth =
      case vKid of
        Just k -> set kid (Just $ HeaderParam Protected (urlToString k))
        Nothing -> set jwk (Just $ HeaderParam Protected vJwkPublic)

-- | Removes private key
jwkPublic :: AsPublicKey a => a -> Either AcmeErr a
jwkPublic = maybe (Left AcmeErrJwkNoPubkey) return . view asPublicKey

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
  -> ExceptT AcmeErr IO AcmeJws
acmeNewJwsBody vObj vUrl vJwkPrivate vJwkPublic vNonce vKid = do
  xh <- either throwError return vHeader
  withExceptT AcmeErrJws $ signJWS payload (Identity (xh, vJwkPrivate))
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
