module Network.ACME
  ( module Network.ACME
  , module Network.ACME.JWS
  , module Network.ACME.Types
  , module Network.ACME.Errors
  ) where

import Control.Monad.Trans.Except
import Crypto.JOSE
import Data.Aeson
import Data.Aeson.Types (emptyObject)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Foldable
import Data.Maybe
import Network.HTTP.Simple
import Network.HTTP.Types
import Network.URI

import Network.ACME.Errors
import Network.ACME.JWS
import Network.ACME.Types

acmeGetPendingChallenge
  :: String -- ^ Type
  -> AcmeObjAuthorization
  -> ExceptT RequestError IO AcmeObjChallenge
acmeGetPendingChallenge t =
  maybeToExceptT (AcmeErrNoChallenge t) . acmeMaybePendingChallenge t

acmeMaybePendingChallenge
  :: String -- ^ Type
  -> AcmeObjAuthorization
  -> Maybe AcmeObjChallenge
acmeMaybePendingChallenge t authz =
  find cond (acmeObjAuthorizationChallenges authz)
  where
    cond x =
      acmeObjChallengeStatus x == "pending" && acmeObjChallengeType x == t

acmeKeyAuthorization :: AcmeObjChallenge
                     -> AcmeObjAccount
                     -> ExceptT RequestError IO String
acmeKeyAuthorization ch acc =
  case acmeObjChallengeToken ch of
    Nothing -> throwE $ AcmeErrNoToken ch
    Just token -> return $ token ++ "." ++ jwkThumbprint (acmeObjAccountKey acc)

newAcmeObjAccountStub :: String -> IO AcmeObjAccount
newAcmeObjAccountStub mail = do
  keyMat <- genKeyMaterial (RSAGenParam 256)
  return $
    AcmeObjAccount
    { acmeObjAccountKey = keyMat
    , acmeObjAccountContact = Just ["mailto:" ++ mail]
    , acmeObjAccountStatus = Nothing
    , acmeObjAccountTermsOfServiceAgreed = Nothing
    , acmeObjAccountOrders = Nothing
    , acmeObjAccountAgreement = Nothing
    }

-- * Perform Requests
-- | Get all supported resources from server
acmePerformDirectory :: AcmeRequestDirectory
                     -> ExceptT RequestError IO AcmeObjDirectory
acmePerformDirectory acmeReq = addDirectory <$> acmeHttpGet acmeReq
  where
    addDirectory x = x {acmeObjDirectory = Just acmeReq}

-- | Registeres new account
acmePerformNewAccount :: AcmeObjAccount
                      -> AcmeObjDirectory
                      -> ExceptT RequestError IO AcmeObjAccount
acmePerformNewAccount acc dir =
  newJwsObj req acc acc dir >>= acmeHttpPostJSON req
  where
    req = fromJust $ acmeObjDirectoryNewReg dir

-- TODO: Only supports bolder legacy
-- | Recover the account uri
acmePerformAccountURI
  :: AcmeObjAccount
  -> AcmeObjDirectory
  -> ExceptT RequestError IO AcmeRequestUpdateAccount
acmePerformAccountURI acc dir = do
  body <- newJwsObj req emptyObject acc dir
  res <- acmeHttpPostResponse req body
  return $
    AcmeRequestUpdateAccount $
    fromJust $ parseURI $ B.unpack $ head $ getResponseHeader "Location" res
  where
    req =
      AcmeRequestAccountURI $
      acmeRequestUrl $ fromJust $ acmeObjDirectoryNewReg dir

-- TODO: Only supports bolder legacy
-- | Update account
acmePerformUpdateAccount :: AcmeObjAccount
                         -> AcmeObjDirectory
                         -> ExceptT RequestError IO AcmeObjAccount
acmePerformUpdateAccount acc dir = do
  req <- acmePerformAccountURI acc dir
  body <- newJwsObj req acc acc dir
  acmeHttpPostJSON req body

-- | New authorization
acmePerformNewAuthz
  :: AcmeObjNewAuthz
  -> AcmeObjAccount
  -> AcmeObjDirectory
  -> ExceptT RequestError IO AcmeObjAuthorization
acmePerformNewAuthz authz acc dir =
  case acmeObjDirectoryNewAuthz dir of
    Nothing -> throwE (RequestNotSupported "new-authz")
    Just req -> newJwsObj req authz acc dir >>= acmeHttpPostJSON req

-- | Existing authorization
acmePerformExistingAuthz
  :: AcmeObjNewAuthz
  -> AcmeObjAccount
  -> AcmeObjDirectory
  -> ExceptT RequestError IO AcmeObjAuthorization
acmePerformExistingAuthz authz acc dir =
  case acmeObjDirectoryNewAuthz dir of
    Nothing -> throwE (RequestNotSupported "new-authz")
    Just req ->
      newJwsObj (reqMod req) (authzMod) acc dir >>= acmeHttpPostJSON req
  where
    authzMod = authz {acmeObjNewAuthzExisting = Just "require"}
    reqMod :: AcmeRequestNewAuthz -> AcmeRequestExistingAuthz
    reqMod = AcmeRequestExistingAuthz . acmeRequestUrl

-- | Respond to challenge
acmePerformRespondChallenge
  :: AcmeRequestChallengeResponse
  -> AcmeObjChallengeResponse
  -> AcmeObjAccount
  -> AcmeObjDirectory
  -> ExceptT RequestError IO AcmeObjChallenge
acmePerformRespondChallenge req ch acc dir =
  newJwsObj req ch acc dir >>= acmeHttpPostJSON req

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
          error $
          show req ++ " does not result in a 'Replay-Nonce': " ++ show res
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
  parseJsonResult req (Just bod') =<<
    httpLBS (setRequestBodyLBS bod' $ newHttpRequest POST req)
  where
    bod' = encode $ toJSONflat bod

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
acmeHttpGet req =
  parseJsonResult req Nothing =<< httpLBS (newHttpRequest GET req)

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
  => a
  -> Maybe L.ByteString
  -> Response L.ByteString
  -> ExceptT RequestError IO b
parseJsonResult req bod res
  | isExpectedResponseStatus res req =
    case eitherDecode (getResponseBody res) of
      Right x -> return x
      Left msg -> throwE $ DecodingError msg $ show $ getResponseBody res
  | otherwise =
    throwE $
    case eitherDecode (getResponseBody res) of
      Right e -> RequestErrorDetail (show req) (getResponseStatus res) e bod
      Left msg ->
        ErrorDecodingError (getResponseStatus res) msg $
        L.unpack $ getResponseBody res

isExpectedResponseStatus
  :: (AcmeRequest b)
  => Response a -> b -> Bool
isExpectedResponseStatus r expected =
  getResponseStatus r == acmeRequestExpectedStatus expected
