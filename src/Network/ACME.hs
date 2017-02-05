module Network.ACME
  ( module Network.ACME
  , module Network.ACME.JWS
  , module Network.ACME.Types
  ) where

import Crypto.JOSE
import Data.Aeson
import Data.Maybe
import Network.HTTP.Simple
import Network.HTTP.Types
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Control.Monad.Trans.Except

import Network.ACME.JWS
import Network.ACME.Types

-- * Perform Requests
-- | Get all supported resources from server
acmePerformDirectory :: AcmeRequestDirectory -> ExceptT RequestError IO AcmeDirectory
acmePerformDirectory acmeReq = addDirectory <$> acmeHttpGet acmeReq
  where
    addDirectory x =
      x
      { acmeDirectory = Just acmeReq
      }

-- | Registeres new account
acmePerformNewReg :: AcmeAccount -> AcmeDirectory -> ExceptT RequestError IO AcmeAccount
acmePerformNewReg acc dir = newJwsObj req acc acc dir >>= acmeHttpPost req
  where
    req = fromJust $ acmeDirectoryNewReg dir

-- | Create new application (handing in a certificate request)
acmePerformNewApp :: AcmeObjNewApp
                  -> AcmeAccount
                  -> AcmeDirectory
                  -> ExceptT RequestError IO AcmeAccount
acmePerformNewApp app acc dir =
  case guessedNewAppRequest of
    Nothing -> throwE (RequestNotSupported "new-app")
    Just req -> newJwsObj req app acc dir >>= acmeHttpPost req
  where
    guessedNewAppRequest =
      case acmeDirectoryNewApp dir of
        Nothing -> acmeDirectoryNewCert dir
        x -> x

-- * Engine
{-|
Creates a signed JWS object in ACME format. This implies interaction with the
ACME server for obtaining a valid nonce for this request.
-}
newJwsObj
  :: (AcmeRequest a, ToJSON o)
  => a -- ^ Usually taken from the 'AcmeDirectory'
  -> o -- ^ Request body
  -> AcmeAccount -- ^ Signing account
  -> AcmeDirectory -- ^ The directory of the server
  -> ExceptT RequestError IO (JWS AcmeJwsHeader)
newJwsObj req obj acc dir = do
  nonce <- acmePerformNonce dir
  RequestJwsError `withExceptT`
    jwsSigned obj (acmeRequestUrl req) (acmeAccountKey acc) nonce

-- | Get new nonce
acmePerformNonce :: AcmeDirectory -> ExceptT RequestError IO AcmeJwsNonce
acmePerformNonce d = do
  f <$> acmeHttpHead req
  where
    f res =
      case getResponseHeader "Replay-Nonce" res of
        nonce:_ -> AcmeJwsNonce $ B.unpack nonce
        [] ->
          error $ show req ++ " does not result in a 'Replay-Nonce': " ++ show res
    req = guessNonceRequest d
    -- Fallback to directory url, since Boulder does not implement /new-nonce/
    guessNonceRequest :: AcmeDirectory -> AcmeRequestNewNonce
    guessNonceRequest AcmeDirectory {..} =
      case acmeDirectoryNewNonce of
        Just x -> x
        Nothing -> AcmeRequestNewNonce (acmeRequestUrl $ fromJust acmeDirectory)

-- | Perform POST query
acmeHttpPost
  :: (AcmeRequest a, FromJSON c)
  => a -- ^ Request
  -> JWS AcmeJwsHeader
  -> ExceptT RequestError IO c
acmeHttpPost req bod = do
  parseJsonResult req =<<
    httpLBS
      (setRequestBodyLBS (encode $ toJSONflat bod) $ newHttpRequest POST req)

-- | Perform GET query
acmeHttpGet
  :: (AcmeRequest a, FromJSON b)
  => a -- ^ Request
  -> ExceptT RequestError IO b
acmeHttpGet req = parseJsonResult req =<< httpLBS (newHttpRequest GET req)

-- | Perform HEAD query
acmeHttpHead
  :: (AcmeRequest a)
  => a -- ^ Request
  -> ExceptT RequestError IO (Response ())
acmeHttpHead req = do
  res <- httpNoBody (newHttpRequest HEAD req)
  if isExpectedResponseStatus res req
    then return res
    else throwE $ RequestErrorStatus (getResponseStatus res)

-- | Transforms abstract ACME to concrete HTTP request
newHttpRequest
  :: (AcmeRequest a)
  => StdMethod
  -> a -- ^ ACME Request
  -> Request
newHttpRequest meth acmeReq =
  setRequestMethod (renderStdMethod meth) $ (parseRequest_ url)
  where
    url = show (acmeRequestUrl acmeReq)

-- ** HTTP-API Error Handling
parseJsonResult
  :: (AcmeRequest a, FromJSON b)
  => a -> Response L.ByteString -> ExceptT RequestError IO b
parseJsonResult req res
  | isExpectedResponseStatus res req =
    return $ (fromJust $ decode $ getResponseBody res)
  | otherwise =
    throwE $
    RequestErrorDetail
      (getResponseStatus res)
      (fromJust $ decode $ getResponseBody res)

isExpectedResponseStatus
  :: (AcmeRequest b)
  => Response a -> b -> Bool
isExpectedResponseStatus r expected =
  getResponseStatus r == acmeRequestExpectedStatus expected

data RequestError
  = RequestErrorDetail Status
                       ProblemDetail
  | RequestErrorStatus Status
  | RequestJwsError Error
  | RequestNotSupported String
  deriving (Show)
