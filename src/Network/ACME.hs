module Network.ACME
  ( module Network.ACME
  , module X
  ) where

import Control.Monad.Trans.Except
import Crypto.JOSE
import Data.Aeson
import Data.Aeson.Types (emptyObject)
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Foldable
import Data.Maybe
import qualified Data.X509 as X509

import Network.ACME.Errors as X
import Network.ACME.HTTP
import Network.ACME.JWS as X
import Network.ACME.Types as X

-- * Perform Requests
-- | Get all supported resources from server
acmePerformDirectory :: AcmeRequestDirectory
                     -> ExceptT RequestError IO AcmeObjDirectory
acmePerformDirectory acmeReq =
  addDirectory <$> (acmeHttpGet acmeReq >>= resBody)
  where
    addDirectory x = x {acmeObjDirectory = Just acmeReq}

-- | Registeres new account
acmePerformNewAccount :: AcmeObjAccount
                      -> AcmeObjDirectory
                      -> ExceptT RequestError IO AcmeObjAccount
acmePerformNewAccount acc dir =
  newJwsObj req acc acc dir >>= acmeHttpPost req >>= resBody
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
  res <- acmeHttpPost req body
  AcmeRequestUpdateAccount <$> resHeaderAsURI "Location" res
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
  acmeHttpPost req body >>= resBody

-- | New authorization
acmePerformNewAuthz
  :: AcmeObjNewAuthz
  -> AcmeObjAccount
  -> AcmeObjDirectory
  -> ExceptT RequestError IO AcmeObjAuthorization
acmePerformNewAuthz authz acc dir =
  case acmeObjDirectoryNewAuthz dir of
    Nothing -> throwE (RequestNotSupported "new-authz")
    Just req -> newJwsObj req authz acc dir >>= acmeHttpPost req >>= resBody

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
      newJwsObj (reqMod req) authzMod acc dir >>= acmeHttpPost req >>= resBody
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
  newJwsObj req ch acc dir >>= acmeHttpPost req >>= resBody

-- | Create new application (handing in a certificate request)
acmePerformNewOrder
  :: AcmeObjOrder
  -> AcmeObjAccount
  -> AcmeObjDirectory
  -> ExceptT RequestError IO X509.SignedCertificate
acmePerformNewOrder app acc dir =
  case guessedNewOrderRequest of
    Nothing -> throwE (RequestNotSupported "new-app")
    Just req -> do
      reqBody <- newJwsObj req app acc dir
      res <- acmeHttpPost req reqBody
      decodeCert $ acmeResponseBody res
  where
    guessedNewOrderRequest =
      case acmeObjDirectoryNewOrder dir of
        Nothing -> acmeObjDirectoryNewCert dir
        x -> x
    decodeCert b =
      case X509.decodeSignedCertificate (L.toStrict b) of
        Right c -> return c
        Left e -> throwE (ErrDecodeX509 e (show b))

-- | Get new nonce
acmePerformNonce :: AcmeObjDirectory -> ExceptT RequestError IO AcmeJwsNonce
acmePerformNonce d =
  AcmeJwsNonce <$> (acmeHttpHead req >>= resHeader "Replay-Nonce")
  where
    req = guessNonceRequest d
    -- Fallback to directory url, since Boulder does not implement /new-nonce/
    guessNonceRequest :: AcmeObjDirectory -> AcmeRequestNewNonce
    guessNonceRequest AcmeObjDirectory {..} =
      case acmeObjDirectoryNewNonce of
        Just x -> x
        Nothing ->
          AcmeRequestNewNonce (acmeRequestUrl $ fromJust acmeObjDirectory)

-- * Utils (maybe move elsewhere)
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
  return
    AcmeObjAccount
    { acmeObjAccountKey = keyMat
    , acmeObjAccountContact = Just ["mailto:" ++ mail]
    , acmeObjAccountStatus = Nothing
    , acmeObjAccountTermsOfServiceAgreed = Nothing
    , acmeObjAccountOrders = Nothing
    , acmeObjAccountAgreement = Nothing
    }

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
