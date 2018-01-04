module Network.ACME
  ( module Network.ACME
  , acmePerformFindAccountURL
  , evalCragT
  ) where

import Control.Concurrent (threadDelay)
import Control.Exception.Lifted (throw, try)
import Control.Monad (msum, void)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (asks)
import Crypto.JOSE (KeyMaterialGenParam(RSAGenParam), genJWK)
import Data.Default.Class (def)
import Data.Maybe (fromMaybe)
import qualified Data.X509 as X509
import Network.HTTP.Client (Manager)
import Network.HTTP.Client.TLS (newTlsManager)
import Network.Socket (HostName)

import Network.ACME.Errors
import Network.ACME.HTTPS
import Network.ACME.Internal (secondsToMicroseconds)
import Network.ACME.JWS
import Network.ACME.Object
import Network.ACME.Type

-- * Perform Requests
-- ** Directory
acmePerformRunner :: CragConfig -> IO (CragReader, CragState)
acmePerformRunner cfg = do
  manager <- newTlsManager
  acmePerformRunner' manager cfg

acmePerformRunner' :: Manager -> CragConfig -> IO (CragReader, CragState)
acmePerformRunner' manager cfg = do
  res <- acmePerformDirectory (cragConfigDirectoryURL cfg) manager
  return
    ( CragReader
        cfg
        CragSetup
          { cragSetupJwkPublic = jwkPublic (cragConfigJwk cfg)
          , cragSetupHttpManager = manager
          }
    , CragState
        { cragStateDirectory = res
        , cragStateNonce = Nothing
        , cragStateKid = Nothing
        })

-- ** Account
-- | Account Creation (Registration)
acmePerformCreateAccount :: AcmeObjStubAccount -> CragT AcmeObjAccount
acmePerformCreateAccount stubAcc =
  resBody <$> acmeHttpJwsPostNewAccount AcmeDirectoryRequestNewAccount stubAcc

-- | Account Update
acmePerformUpdateAccount :: AcmeObjAccount -> CragT AcmeObjAccount
acmePerformUpdateAccount newAcc = do
  url <- acmePerformFindAccountURL
  resBody <$> acmeHttpJwsPostUrl url newAcc

-- | Key Roll-over
acmePerformAccountKeyRollover ::
     JWK -- ^ New key
  -> CragT AcmeObjAccount
acmePerformAccountKeyRollover newJWK = do
  accURL <- acmePerformFindAccountURL
  let obj = AcmeObjAccountKeyRollover accURL newJWK
  resBody <$> acmeHttpJwsPost AcmeDirectoryRequestKeyChange obj

-- ** Certificate
-- | Create new application (handing in a certificate request)
acmePerformNewOrder :: AcmeObjNewOrder -> CragT (URL, AcmeObjOrder)
acmePerformNewOrder ord = do
  res <- acmeHttpJwsPost AcmeDirectoryRequestNewOrder ord
  loc <- resHeaderAsURL "Location" res
  return (loc, resBody res)
  -- :: X509.SignedCertificate

acmePerformGetOrder :: URL -> CragT AcmeObjOrder
acmePerformGetOrder url = resBody <$> acmeHttpGet url

acmePerformWaitUntilOrderValid :: URL -> CragT AcmeObjOrder
acmePerformWaitUntilOrderValid url = poll
  where
    poll = do
      ord <- acmePerformGetOrder url
      case acmeObjOrderStatus ord of
        "pending" -> retry poll
        "processing" -> retry poll
        "valid" -> return ord
        s -> error $ "state not good: " ++ s

acmePerformWaitUntilAuthorizationValid :: URL -> CragT AcmeObjAuthorization
acmePerformWaitUntilAuthorizationValid url = poll
  where
    poll = do
      ord <- acmePerformGetAuthorization url
      case acmeObjAuthorizationStatus ord of
        "pending" -> retry poll
        "processing" -> retry poll
        "valid" -> return ord
        s -> error $ "state not good: " ++ s

retry :: CragT a -> CragT a
retry poll = do
  i <- asks (cragConfigPollingInterval . cragConfig)
  liftIO $ threadDelay (secondsToMicroseconds i)
  poll

-- ** Authorization
acmePerformGetAuthorizations :: AcmeObjOrder -> CragT [AcmeObjAuthorization]
acmePerformGetAuthorizations =
  mapM acmePerformGetAuthorization . acmeObjOrderAuthorizations

acmePerformGetAuthorization :: URL -> CragT AcmeObjAuthorization
acmePerformGetAuthorization url = resBody <$> acmeHttpGet url

type ChallengeResponder a
   = HostName -> AcmeKeyAuthorization -> (IO () -> CragT AcmeObjChallenge) -- ^ Perform challenge response, first argument is rollback
                                          -> CragT a

acmePerformChallengeResponses ::
     [(String, ChallengeResponder a)]
  -> [AcmeObjAuthorization]
  -> CragT [a] -- ^ 
acmePerformChallengeResponses fs as = do
  let actions =
        map getF (filter ((== "pending") . acmeObjAuthorizationStatus) as)
  mapM apply actions
  where
    cs :: AcmeObjAuthorization -> [(String, AcmeObjChallenge)]
    cs a =
      map (\x -> (acmeObjChallengeType x, x)) $ acmeObjAuthorizationChallenges a
    g a = msum [(,) f . (,) a <$> lookup chType (cs a) | (chType, f) <- fs]
    getF a =
      fromMaybe (throw $ AcmeErrNoFullfillableChallenge (map fst fs) a) (g a)
    apply (f, (a, ch)) = do
      argKey <- acmeKeyAuthorization ch
      let argId = acmeObjIdentifierValue (acmeObjAuthorizationIdentifier a)
          authz = acmeChallengeRespond (acmeObjChallengeUrl ch) argKey
      f argId argKey authz

acmePerformFinalizeOrder :: AcmeObjOrder -> Base64Octets -> CragT AcmeObjOrder
acmePerformFinalizeOrder order =
  acmePerformFinalizeOrder' (acmeObjOrderFinalize order)

acmePerformFinalizeOrder' :: URL -> Base64Octets -> CragT AcmeObjOrder
acmePerformFinalizeOrder' url csr =
  resBody <$> acmeHttpJwsPostUrl url (AcmeObjFinalizeOrder csr)

-- | Respond to challenge
acmeChallengeRespond ::
     URL -> AcmeKeyAuthorization -> IO () -> CragT AcmeObjChallenge
acmeChallengeRespond req k cleanup = do
  res <- try $ resBody <$> acmeHttpJwsPostUrl req (AcmeObjChallengeResponse k)
  case res of
    Right r -> return r
    Left e -> do
      _ <- liftIO cleanup
      throw (e :: AcmeErr)

acmeChallengeRespond' :: URL -> AcmeKeyAuthorization -> CragT AcmeObjChallenge
acmeChallengeRespond' req k = acmeChallengeRespond req k (return ())

-- | Revoke
acmePerformRevokeCertificate :: AcmeObjRevokeCertificate -> CragT ()
acmePerformRevokeCertificate obj =
  void (acmeHttpJwsPost AcmeDirectoryRequestRevokeCert obj)

-- * Utils
-- ** Object generation
acmeNewObjAccountStub :: String -> IO (AcmeObjStubAccount, JWK)
acmeNewObjAccountStub mail = do
  keyMat <- genJWK (RSAGenParam 256)
  return
    ( def
        { acmeObjStubAccountContact = Just ["mailto:" ++ mail]
        , acmeObjStubAccountTermsOfServiceAgreed = Just True
        }
    , keyMat)

acmeNewJWK :: IO JWK
acmeNewJWK = genJWK (RSAGenParam 256)

acmeNewObjOrder :: [String] -> AcmeObjNewOrder
acmeNewObjOrder xs =
  AcmeObjNewOrder
    { acmeObjNewOrderIdentifiers = map toId xs
    , acmeObjNewOrderNotBefore = Nothing
    , acmeObjNewOrderNotAfter = Nothing
    }
  where
    toId v =
      AcmeObjIdentifier
        {acmeObjIdentifierType = "dns", acmeObjIdentifierValue = v}

acmeNewObjRevokeCertificate ::
     X509.SignedCertificate -> AcmeObjRevokeCertificate
acmeNewObjRevokeCertificate crt =
  AcmeObjRevokeCertificate
    { acmeObjRevokeCertificateCertificate =
        Base64Octets (X509.encodeSignedObject crt)
    , acmeObjRevokeCertificateReason = Nothing
    }

-- ** Other
-- | keyAuthorization for a given challenge
acmeKeyAuthorization :: AcmeObjChallenge -> CragT AcmeKeyAuthorization
acmeKeyAuthorization ch = do
  jwk <- asks (cragSetupJwkPublic . cragSetup)
  return . AcmeKeyAuthorization $ acmeKeyAuthorization' ch jwk

keyAuthorization :: AcmeKeyAuthorization -> String
keyAuthorization (AcmeKeyAuthorization x) = x

keyAuthorizationToken :: AcmeKeyAuthorization -> String
keyAuthorizationToken = takeWhile (/= '.') . keyAuthorization

keyAuthorizationHttpPath :: AcmeKeyAuthorization -> String
keyAuthorizationHttpPath x =
  "/.well-known/acme-challenge/" ++ keyAuthorizationToken x

acmeKeyAuthorization' :: AcmeObjChallenge -> JWK -> String
acmeKeyAuthorization' ch acc =
  acmeObjChallengeToken ch ++ "." ++ jwkThumbprint acc
