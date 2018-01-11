module Network.ACME.HTTPS.Internal where

import Control.Concurrent (threadDelay)
import Control.Exception
import Control.Monad.Except (ExceptT, catchError, lift, throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (asks)
import Control.Monad.State (gets, modify)
import Data.Aeson (FromJSON, ToJSON, eitherDecode, encode)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.CaseInsensitive (CI, mk)
import Data.Default.Class (def)
import Data.PEM (pemContent, pemParseLBS)
import Data.Time
  ( UTCTime
  , defaultTimeLocale
  , diffUTCTime
  , getCurrentTime
  , parseTimeM
  )
import Network.HTTP.Client
  ( HttpException(HttpExceptionRequest)
  , Manager
  , Request
  , RequestBody(RequestBodyLBS)
  , Response
  , getUri
  , httpLbs
  , method
  , method
  , parseRequest_
  , requestBody
  , responseBody
  , responseHeaders
  , responseStatus
  )
import Network.HTTP.Types
  ( HeaderName
  , StdMethod(GET, HEAD, POST)
  , hContentType
  , renderStdMethod
  )
import Text.Read (readMaybe)

import Network.ACME.Error
import Network.ACME.JWS
import Network.ACME.Object
import Network.ACME.Type

-- * To Be Removed
maxRetries :: Int
maxRetries = 20

-- * Operations
-- | Get new nonce
acmePerformNonce :: CragT AcmeJwsNonce
acmePerformNonce = do
  req <- gets (acmeObjDirectoryNewNonce . cragStateDirectory)
  h <- httpsHead req
  AcmeJwsNonce <$> resHeader "Replay-Nonce" h

acmePerformFindAccountURL :: CragT URL
acmePerformFindAccountURL = do
  url <- gets cragStateKid
  case url of
    Just u -> return u
    Nothing -> do
      res <-
        httpsJwsPostNewAccount
          AcmeDirectoryRequestNewAccount
          def {acmeObjStubAccountOnlyReturnExisting = Just True}
      resHeaderAsURL "Location" res

-- * Server Response
type ResponseLbs = Response L.ByteString

getHeader :: HeaderName -> ResponseLbs -> Maybe String
getHeader h r = B.unpack <$> getResponseHeader h r

getResponseMimeType :: ResponseLbs -> Maybe (CI B.ByteString)
getResponseMimeType r =
  mk . B.takeWhile (`notElem` [';', ' ']) <$> getResponseHeader hContentType r

getResponseHeader :: HeaderName -> ResponseLbs -> Maybe B.ByteString
getResponseHeader name = lookup name . responseHeaders

resHeader :: HeaderName -> ResponseLbs -> CragT String
resHeader h r = maybe (error "AcmeErrHeaderNotFound") return (getHeader h r)

resHeaderAsURL :: HeaderName -> ResponseLbs -> CragT URL
resHeaderAsURL x ys = do
  h <- resHeader x ys
  case parseURL h of
    Just u -> return u
    Nothing ->
      throwError
        AcmeErrDecodingHeader
          {acmeErrHeaderName = show x, acmeErrHeaderValue = h}

resRetryAfter :: ResponseLbs -> IO (Maybe Int)
resRetryAfter r = do
  currentTime <- getCurrentTime
  return $ do
    h <- getHeader "Retry-After" r
    case parseHttpTime h of
      Just t -> return . ceiling $ diffUTCTime t currentTime
      Nothing -> readMaybe h

-- | RFC 1123 only
parseHttpTime :: String -> Maybe UTCTime
parseHttpTime = parseTimeM True defaultTimeLocale "%a, %d %b %0Y %T GMT"

resBody :: FromJSON a => ResponseLbs -> CragT a
resBody res = lift . lift $ resBody' res

resBody' :: FromJSON a => ResponseLbs -> ExceptT AcmeErr IO a
resBody' res =
  case eitherDecode (responseBody res) of
    Right x -> return x
    Left msg ->
      throwError
        AcmeErrDecodingBody {acmeErrMessage = msg, acmeErrBody = show res}

parsePEMBody :: ResponseLbs -> [B.ByteString]
parsePEMBody res =
  case pemParseLBS (responseBody res) of
    Left e -> error e --ErrDecodingPEM e
    Right v -> map pemContent v

-- * State Operations
cragStateAddNonce :: ResponseLbs -> CragT ()
cragStateAddNonce r =
  cragStateSetNonce $ AcmeJwsNonce <$> getHeader "Replay-Nonce" r

cragStateSetNonce :: Maybe AcmeJwsNonce -> CragT ()
cragStateSetNonce n = modify (\s -> s {cragStateNonce = n})

cragStateSetKid :: Maybe URL -> CragT ()
cragStateSetKid k = modify (\s -> s {cragStateKid = k})

cragStateGetNonce :: CragT AcmeJwsNonce
cragStateGetNonce = do
  nonce <- gets cragStateNonce
  case nonce of
    Just x -> return x
    Nothing -> acmePerformNonce

cragStateGetDirectoryEntry :: AcmeDirectoryRequest -> CragT URL
cragStateGetDirectoryEntry req = do
  url <- gets (acmeRequestUrl req . cragStateDirectory)
  maybe (throwError $ AcmeErrRequestNotSupported req) return url

-- * Perform HTTPS
httpsJwsPostNewAccount ::
     (ToJSON a) => AcmeDirectoryRequest -> a -> CragT ResponseLbs
httpsJwsPostNewAccount r x = do
  url <- cragStateGetDirectoryEntry r
  httpsJwsPost' 0 False url x

httpsJwsPostUrl :: (ToJSON a) => URL -> a -> CragT ResponseLbs
httpsJwsPostUrl = httpsJwsPost' 0 True

httpsJwsPost :: (ToJSON a) => AcmeDirectoryRequest -> a -> CragT ResponseLbs
httpsJwsPost r x = do
  url <- cragStateGetDirectoryEntry r
  httpsJwsPostUrl url x

httpsJwsPost' :: (ToJSON a) => Int -> Bool -> URL -> a -> CragT ResponseLbs
httpsJwsPost' retried withKid url bod = do
  vKid <- accURL
  cragStateSetKid vKid
  nonce <- cragStateGetNonce
  vJwkPublic <- asks (cragSetupJwkPublic . cragSetup)
  vJwkPrivate <- asks (cragConfigJwk . cragConfig)
  req <- lift . lift $ acmeNewJwsBody bod url vJwkPrivate vJwkPublic nonce vKid
  res <- catchError (httpsPost url req) handler
  cragStateAddNonce res
  return res
  where
    handler :: AcmeErr -> CragT ResponseLbs
    handler e@AcmeErrDetail {}
      | errBadNonce e || retried >= maxRetries = do
        cragStateSetNonce Nothing
        httpsJwsPost' (retried + 1) withKid url bod
      | otherwise = throwError e
    handler e = throwError e
    accURL :: CragT (Maybe URL)
    accURL
      | withKid = Just <$> acmePerformFindAccountURL
      | otherwise = return Nothing

-- ** Lower level
https :: Request -> CragT ResponseLbs
https request = do
  cragLog $ reqStr request
  cfg <- asks cragConfig
  manager <- asks (cragSetupHttpManager . cragSetup)
  logger <- asks (cragSetupLogger . cragSetup)
  lift . lift $ https' request cfg manager logger
  where
    reqStr x = show (method x) ++ " " ++ show (getUri x)

https' ::
     Request
  -> CragConfig
  -> Manager
  -> CragLogger
  -> ExceptT AcmeErr IO ResponseLbs
https' request cfg manager logger = perform 20
  where
    perform :: Int -> ExceptT AcmeErr IO ResponseLbs
    perform i = do
      result <- liftIO $ try $ httpLbs request manager
      case result of
        Left e
          | i < 0 -> throwError $ AcmeErrHTTPS e
          | otherwise -> do
            liftIO $ cragLog' logger $ show e
            liftIO $ threadDelay 100000
            perform (i - 1)
        Right r -> return r

-- | Perform POST query
httpsPost :: URL -> AcmeJws -> CragT ResponseLbs
httpsPost req bod =
  https (newRequest POST req) {requestBody = RequestBodyLBS bod'} >>=
  parseResult req (Just bod')
  where
    bod' = encode bod

-- | Perform GET query
httpsGet ::
     URL -- ^ Request
  -> CragT ResponseLbs
httpsGet url = https (newRequest GET url)

httpsGet' ::
     URL -- ^ Request
  -> CragConfig
  -> Manager
  -> CragLogger
  -> ExceptT AcmeErr IO ResponseLbs
httpsGet' url
  --parseResult req Nothing $
 = https' (newRequest GET url)

-- | Perform HEAD query
httpsHead ::
     URL -- ^ Request
  -> CragT ResponseLbs
httpsHead url = https (newRequest HEAD url) >>= parseResult url Nothing

-- | Transforms abstract ACME to concrete HTTP request
newRequest :: StdMethod -> URL -> Request
newRequest meth acmeReq = (parseRequest_ url) {method = renderStdMethod meth}
  where
    url = urlToString acmeReq

-- ** Utils
parseResult ::
     URL
  -> Maybe L.ByteString -- ^ Body
  -> Response L.ByteString
  -> CragT ResponseLbs
parseResult req bod res =
  if getResponseMimeType res /= Just "application/problem+json"
    then return res
    else case eitherDecode (responseBody res) of
           Right e ->
             throwError
               AcmeErrDetail
                 { acmeErrRequest = req
                 , acmeErrHttpStatus = responseStatus res
                 , acmeErrProblemDetail = e
                 , acmeErrRequestBody = bod
                 }
           Left msg ->
             throwError
               AcmeErrDecodingProblemDetail
                 { acmeErrHttpStatus = responseStatus res
                 , acmeErrMessage = msg
                 , acmeErrResponseBody = L.unpack $ responseBody res
                 }
