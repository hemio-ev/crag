module Network.ACME
  ( module Network.ACME
  , module Network.ACME.JWS
  , module Network.ACME.Types
  ) where

import Crypto.JOSE
import Data.Aeson
import Data.Aeson.Types (emptyObject)
import Data.Maybe
import Network.HTTP.Simple
import Network.HTTP.Types
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Control.Monad.Trans.Except
import Network.URI
import Data.Yaml.Pretty

import Network.ACME.JWS
import Network.ACME.Types

-- * Perform Requests
-- | Get all supported resources from server
acmePerformDirectory :: AcmeRequestDirectory -> ExceptT RequestError IO AcmeObjDirectory
acmePerformDirectory acmeReq = addDirectory <$> acmeHttpGet acmeReq
  where
    addDirectory x =
      x
      { acmeObjDirectory = Just acmeReq
      }

-- | Registeres new account
acmePerformNewAccount :: AcmeObjAccount
                      -> AcmeObjDirectory
                      -> ExceptT RequestError IO AcmeObjAccount
acmePerformNewAccount acc dir = newJwsObj req acc acc dir >>= acmeHttpPostJSON req
-- TODO: Only supports bolder legacy
  where
    req = fromJust $ acmeObjDirectoryNewReg dir

-- | Recover the account uri
acmePerformAccountURI :: AcmeObjAccount
                      -> AcmeObjDirectory
                      -> ExceptT RequestError IO AcmeRequestUpdateAccount
acmePerformAccountURI acc dir = do
  body <- newJwsObj req emptyObject acc dir
  res <- acmeHttpPostResponse req body
  return $
    AcmeRequestUpdateAccount $
    fromJust $ parseURI $ B.unpack $ head $ getResponseHeader "Location" res
-- TODO: Only supports bolder legacy
  where
    req =
      AcmeRequestAccountURI $
      acmeRequestUrl $ fromJust $ acmeObjDirectoryNewReg dir

-- | Update account
acmePerformUpdateAccount :: AcmeObjAccount
                         -> AcmeObjDirectory
                         -> ExceptT RequestError IO AcmeObjAccount
acmePerformUpdateAccount acc dir = do
  req <- acmePerformAccountURI acc dir
  body <- newJwsObj req acc acc dir
  acmeHttpPostJSON req body

-- | Create new application (handing in a certificate request)
acmePerformNewOrder
  :: AcmeObjOrder
  -> AcmeObjAccount
  -> AcmeObjDirectory
  -> ExceptT RequestError IO AcmeObjAccount -- TODO: WRONG TYPE
acmePerformNewOrder app acc dir =
  case guessedNewOrderRequest of
    Nothing -> throwE (RequestNotSupported "new-app")
    Just req -> newJwsObj req app acc dir >>= acmeHttpPostJSON req
  where
    guessedNewOrderRequest =
      case acmeObjDirectoryNewOrder dir of
        Nothing -> acmeObjDirectoryNewCert dir
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
  -> AcmeObjAccount -- ^ Signing account
  -> AcmeObjDirectory -- ^ The directory of the server
  -> ExceptT RequestError IO (JWS AcmeJwsHeader)
newJwsObj req obj acc dir = do
  nonce <- acmePerformNonce dir
  RequestJwsError `withExceptT`
    jwsSigned obj (acmeRequestUrl req) (acmeObjAccountKey acc) nonce

-- | Get new nonce
acmePerformNonce :: AcmeObjDirectory -> ExceptT RequestError IO AcmeJwsNonce
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
    guessNonceRequest :: AcmeObjDirectory -> AcmeRequestNewNonce
    guessNonceRequest AcmeObjDirectory {..} =
      case acmeObjDirectoryNewNonce of
        Just x -> x
        Nothing ->
          AcmeRequestNewNonce (acmeRequestUrl $ fromJust acmeObjDirectory)

-- | Perform POST query
acmeHttpPostJSON
  :: (AcmeRequest a, FromJSON c)
  => a -- ^ Request
  -> JWS AcmeJwsHeader
  -> ExceptT RequestError IO c
acmeHttpPostJSON req bod = do
  parseJsonResult req =<<
    httpLBS
      (setRequestBodyLBS (encode $ toJSONflat bod) $ newHttpRequest POST req)

-- | Perform POST query
acmeHttpPostResponse
  :: (AcmeRequest a)
  => a -- ^ Request
  -> JWS AcmeJwsHeader
  -> ExceptT RequestError IO (Response L.ByteString)
acmeHttpPostResponse req bod = do
  res <-
    httpLBS
      (setRequestBodyLBS (encode $ toJSONflat bod) $ newHttpRequest POST req)
  if isExpectedResponseStatus res req
    then return res
    else throwE $ RequestErrorStatus (getResponseStatus res)

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
  | otherwise --error $ show $ res
   =
    throwE $
    RequestErrorDetail
      (show req)
      (getResponseStatus res)
      (fromJust $ decode $ getResponseBody res)

isExpectedResponseStatus
  :: (AcmeRequest b)
  => Response a -> b -> Bool
isExpectedResponseStatus r expected =
  getResponseStatus r == acmeRequestExpectedStatus expected

data RequestError
  = RequestErrorDetail String
                       Status
                       ProblemDetail
  | RequestErrorStatus Status
  | RequestJwsError Error
  | RequestNotSupported String
  deriving (Show)

showRequestError :: RequestError -> String
showRequestError (RequestErrorDetail r s d) =
  "Request: " ++
  r ++
  "\nStatus: " ++
  showStatus s ++ "\n\nDetails:\n" ++ B.unpack (encodePretty defConfig d)
showRequestError x = show x

showStatus :: Status -> String
showStatus Status {..} = show statusCode ++ " " ++ B.unpack statusMessage
