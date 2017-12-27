module Network.ACME.HTTP
  ( AcmeT
  , acmeHttpGet
  , acmeHttpJwsPost
  , acmeHttpJwsPostNewAccount
  , acmeHttpJwsPostUrl
  , getResponseBody
  , resBody
  , resHeaderAsURL
  , acmePerformDirectory
  ) where

import Control.Exception.Lifted (handle, throw)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.State (StateT, gets, modify)
import Data.Aeson (FromJSON, ToJSON, eitherDecode, encode)
import Data.Aeson.Types (emptyObject)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.CaseInsensitive (CI, mk)
import Data.Maybe (fromMaybe, listToMaybe)
import Network.HTTP.Client (Manager, Request, Response, httpLbs, parseRequest_)
import Network.HTTP.Simple
  ( getResponseBody
  , getResponseHeader
  , getResponseStatus
  , setRequestBodyLBS
  , setRequestMethod
  )
import Network.HTTP.Types
  ( HeaderName
  , StdMethod(GET, HEAD, POST)
  , hContentType
  , renderStdMethod
  )

import Network.ACME.Errors
import Network.ACME.JWS
import Network.ACME.Object
import Network.ACME.Type

maxRetries :: Int
maxRetries = 20

type AcmeT = StateT AcmeState IO

acmeDictionaryUrl :: AcmeDirectoryRequest -> AcmeT URL
acmeDictionaryUrl req = do
  url <- gets (acmeRequestUrl req . acmeStateDirectory)
  return $ fromMaybe (throw $ AcmeErrRequestNotSupported req) url

-- | Get all supported resources from server
acmePerformDirectory :: URL -> Manager -> IO AcmeObjDirectory
acmePerformDirectory acmeReq manager = resBody <$> acmeHttpGet' acmeReq manager

-- ** Nonce
-- | Get new nonce
acmePerformNonce :: AcmeT AcmeJwsNonce
acmePerformNonce = do
  req <- gets (acmeObjDirectoryNewNonce . acmeStateDirectory)
  h <- acmeHttpHead req
  liftIO $ AcmeJwsNonce <$> resHeader "Replay-Nonce" h

-- ** ACME Server Response
type AcmeResponse = Response L.ByteString

--type Headers = [(HeaderName, B.ByteString)]
getHeader :: HeaderName -> AcmeResponse -> Maybe String
getHeader h r = B.unpack <$> listToMaybe (getResponseHeader h r)

resHeader :: HeaderName -> AcmeResponse -> IO String
resHeader h r = maybe (error "AcmeErrHeaderNotFound") return (getHeader h r)

--  $ AcmeErrHeaderNotFound h (Protocoll violation)
resHeaderAsURL :: HeaderName -> AcmeResponse -> IO URL
resHeaderAsURL x ys = do
  h <- resHeader x ys
  case parseURL h of
    Just u -> return u
    Nothing ->
      throw
        AcmeErrDecodingHeader
        {acmeErrHeaderName = show x, acmeErrHeaderValue = h}

resBody :: FromJSON a => AcmeResponse -> a
resBody res =
  case eitherDecode (getResponseBody res) of
    Right x -> x
    Left msg ->
      throw AcmeErrDecodingBody {acmeErrMessage = msg, acmeErrBody = show res}

acmeTAddNonce :: AcmeResponse -> AcmeT ()
acmeTAddNonce r = acmeTSetNonce $ AcmeJwsNonce <$> getHeader "Replay-Nonce" r

acmeTSetNonce :: Maybe AcmeJwsNonce -> AcmeT ()
acmeTSetNonce n = modify (\s -> s {acmeStateNonce = n})

acmeTSetKid :: Maybe URL -> AcmeT ()
acmeTSetKid k = modify (\s -> s {acmeStateKid = k})

acmeTGetNonce :: AcmeT AcmeJwsNonce
acmeTGetNonce = do
  nonce <- gets acmeStateNonce
  case nonce of
    Just x -> return x
    Nothing -> acmePerformNonce

acmeHttpJwsPostNewAccount ::
     (ToJSON a) => AcmeDirectoryRequest -> a -> AcmeT AcmeResponse
acmeHttpJwsPostNewAccount r x = do
  url <- acmeDictionaryUrl r
  acmeHttpJwsPost' 0 False url x

acmeHttpJwsPostUrl :: (ToJSON a) => URL -> a -> AcmeT AcmeResponse
acmeHttpJwsPostUrl = acmeHttpJwsPost' 0 True

acmeHttpJwsPost :: (ToJSON a) => AcmeDirectoryRequest -> a -> AcmeT AcmeResponse
acmeHttpJwsPost r x = do
  url <- acmeDictionaryUrl r
  acmeHttpJwsPostUrl url x

errBadNonce :: AcmeErr -> Bool
errBadNonce AcmeErrDetail {acmeErrProblemDetail = d}
  | (show <$> problemDetailType d) == Just "urn:ietf:params:acme:error:badNonce" =
    True
  | otherwise = False
errBadNonce _ = False

acmeHttpJwsPost' :: (ToJSON a) => Int -> Bool -> URL -> a -> AcmeT AcmeResponse
acmeHttpJwsPost' retried withKid url bod = do
  vKid <- acmePerformFindAccountURL
  acmeTSetKid vKid
  nonce <- acmeTGetNonce
  vJwkPublic <- gets acmeStateJwkPublic
  vJwkPrivate <- gets acmeStateJwkPrivate
  req <- liftIO $ acmeNewJwsBody bod url vJwkPrivate vJwkPublic nonce vKid
  res <- handle handler $ acmeHttpPost url req
  acmeTAddNonce res
  return res
  where
    handler :: AcmeErr -> AcmeT AcmeResponse
    handler e@AcmeErrDetail {}
      | errBadNonce e || retried >= maxRetries = do
        acmeTSetNonce Nothing
        acmeHttpJwsPost' (retried + 1) withKid url bod
      | otherwise = throw e
    handler e = throw e
    acmePerformFindAccountURL :: AcmeT (Maybe URL)
    acmePerformFindAccountURL
      | withKid =
        Just <$> do
          res <-
            acmeHttpJwsPostNewAccount AcmeDirectoryRequestNewAccount emptyObject
          liftIO $ resHeaderAsURL "Location" res
      | otherwise = return Nothing

-- ** Perform ACME Server Request
-- | Perform POST query
acmeHttpPost :: URL -> AcmeJws -> AcmeT AcmeResponse
acmeHttpPost req bod = do
  manager <- gets acmeStateHttpManager
  parseResult req (Just bod') $
    httpLbs (setRequestBodyLBS bod' $ newHttpRequest POST req) manager
  where
    bod' = encode bod

-- | Perform GET query
acmeHttpGet ::
     URL -- ^ Request
  -> AcmeT AcmeResponse
acmeHttpGet req = do
  manager <- gets acmeStateHttpManager
  liftIO $ acmeHttpGet' req manager

acmeHttpGet' ::
     URL -- ^ Request
  -> Manager
  -> IO AcmeResponse
acmeHttpGet' req
  --parseResult req Nothing $ 
 = httpLbs (newHttpRequest GET req)

-- | Perform HEAD query
acmeHttpHead ::
     URL -- ^ Request
  -> AcmeT AcmeResponse
acmeHttpHead req = do
  manager <- gets acmeStateHttpManager
  parseResult req Nothing $ httpLbs (newHttpRequest HEAD req) manager

-- | Transforms abstract ACME to concrete HTTP request
newHttpRequest :: StdMethod -> URL -> Request
newHttpRequest meth acmeReq =
  setRequestMethod (renderStdMethod meth) (parseRequest_ url)
  where
    url = urlToString acmeReq

-- hContentType
-- takeWhile ((`notElem` [';', ' '])) 
-- B.takeWhile ((`notElem` [';', ' '])) . getResponseHeader hContentType
getResponseMimeType :: Response a -> Maybe (CI B.ByteString)
getResponseMimeType r =
  mk . B.takeWhile (`notElem` [';', ' ']) <$>
  listToMaybe (getResponseHeader hContentType r)

-- ** Utils
parseResult ::
     URL
  -> Maybe L.ByteString -- ^ Body
  -> IO (Response L.ByteString)
  -> AcmeT AcmeResponse
parseResult req bod resIO = do
  res <- liftIO resIO
  if getResponseMimeType res /= Just "application/problem+json"
    then return res
    else case eitherDecode (getResponseBody res) of
           Right e ->
             throw
               AcmeErrDetail
               { acmeErrRequest = req
               , acmeErrHttpStatus = getResponseStatus res
               , acmeErrProblemDetail = e
               , acmeErrRequestBody = bod
               }
           Left msg ->
             throw
               AcmeErrDecodingProblemDetail
               { acmeErrHttpStatus = getResponseStatus res
               , acmeErrMessage = msg
               , acmeErrResponseBody = L.unpack $ getResponseBody res
               }
  --where
  --  isExpectedResponseStatus r expected = True
      --getResponseStatus r == undefined -- acmeRequestExpectedStatus expected
