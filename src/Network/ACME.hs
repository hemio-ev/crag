module Network.ACME
  ( module Network.ACME
  , acmePerformFindAccountURL
  , evalCragT
  ) where

import Control.Concurrent (threadDelay)
import Control.Monad (void)
import Control.Monad.Except (ExceptT, catchError, throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (asks)
import Crypto.JOSE (KeyMaterialGenParam(RSAGenParam), genJWK)
import Data.Aeson (FromJSON)
import qualified Data.ByteString.Char8 as B
import Data.Default.Class (def)
import Data.Maybe (fromMaybe, listToMaybe)
import Data.PEM (PEM(PEM), pemWriteBS)
import qualified Data.X509 as X509
import Network.HTTP.Client (Manager)
import Network.HTTP.Client.TLS (newTlsManager)

import Network.ACME.Error
import Network.ACME.HTTPS
import Network.ACME.HTTPS.Internal (httpsGet', resBody')
import Network.ACME.Internal (secondsToMicroseconds)
import Network.ACME.JWS
import Network.ACME.Object
import Network.ACME.Type

-- * Perform Requests
-- ** Basic
http01 :: String
http01 = "http-01"

dns01 :: String
dns01 = "dns-01"

tlsSni02 :: String
tlsSni02 = "tls-sni-02"

obtainCertificate ::
     CertificateForm a
  => [String] -- ^ Domains
  -> Base64Octets -- ^ CSR
  -> [(String, ChallengeReaction)] -- ^ Challenge reactions
  -> CragT [a] -- ^ Certificate chain?
obtainCertificate domains cert reactions = do
  (orderURL, orderObj) <- acmePerformNewOrder (acmeNewObjOrder domains)
  _ <-
    acmePerformGetAuthorizations orderObj >>=
    acmePerformChallengeReaction reactions
  -- wait until server has validated
  _ <- acmePerformWaitUntilOrderReady orderURL
  -- finalize: submit CSR
  _ <- acmePerformFinalizeOrder orderObj cert
  -- wait until certificate issued
  finalOrder <- acmePerformWaitUntilOrderValid orderURL
  -- download certificate
  retrieveCertificate finalOrder

-- ** Directory
-- | Get all supported resources from server
retrieveDirectory ::
     CragConfig -> Manager -> CragLogger -> ExceptT AcmeErr IO AcmeObjDirectory
retrieveDirectory cfg manager logger =
  resBody' =<< httpsGet' (cragConfigDirectoryURL cfg) cfg manager logger

acmePerformRunner :: CragConfig -> ExceptT AcmeErr IO (CragReader, CragState)
acmePerformRunner cfg = do
  manager <- newTlsManager
  acmePerformRunner' manager Nothing cfg

acmePerformRunner' ::
     Manager
  -> CragLogger -- ^ Logger
  -> CragConfig
  -> ExceptT AcmeErr IO (CragReader, CragState)
acmePerformRunner' manager logger cfg = do
  res <- retrieveDirectory cfg manager logger
  publicKey <- either throwError return $ jwkPublic (cragConfigJwk cfg)
  return
    ( CragReader
        cfg
        CragSetup
          { cragSetupJwkPublic = publicKey
          , cragSetupHttpManager = manager
          , cragSetupLogger = logger
          }
    , CragState
        { cragStateDirectory = res
        , cragStateNonce = Nothing
        , cragStateKid = Nothing
        })

-- ** Account
-- | Account Creation (Registration)
acmePerformCreateAccount :: AcmeObjStubAccount -> CragT (URL, AcmeObjAccount)
acmePerformCreateAccount stubAcc = do
  res <- httpsJwsPostNewAccount AcmeDirectoryRequestNewAccount stubAcc
  loc <- resHeaderAsURL "Location" res
  acc <- resBody res
  return (loc, acc)

-- | Account Update
acmePerformUpdateAccount :: AcmeObjAccount -> CragT AcmeObjAccount
acmePerformUpdateAccount newAcc = do
  url <- acmePerformFindAccountURL
  resBody =<< httpsJwsPostUrl url newAcc

-- | Key Roll-over
acmePerformAccountKeyRollover ::
     JWK -- ^ New key
  -> CragT AcmeObjAccount
acmePerformAccountKeyRollover newJWK = do
  accURL <- acmePerformFindAccountURL
  let obj = AcmeObjAccountKeyRollover accURL newJWK
  resBody =<< httpsJwsPost AcmeDirectoryRequestKeyChange obj

-- ** Certificate
-- | Create order (handing in a certificate request)
acmePerformNewOrder :: AcmeObjNewOrder -> CragT (URL, AcmeObjOrder)
acmePerformNewOrder ord = do
  res <- httpsJwsPost AcmeDirectoryRequestNewOrder ord
  loc <- resHeaderAsURL "Location" res
  newOrd <- resBody res
  return (loc, newOrd)

acmePerformWaitUntilOrderReady :: URL -> CragT AcmeObjOrder
acmePerformWaitUntilOrderReady url = poll
  where
    poll = do
      ord <- acmePerformGetObject url
      case acmeObjOrderStatus ord of
        "pending" -> retry poll
        "ready" -> return ord
        s -> error $ "state not good: " ++ s

acmePerformWaitUntilOrderValid :: URL -> CragT AcmeObjOrder
acmePerformWaitUntilOrderValid url = poll
  where
    poll = do
      ord <- acmePerformGetObject url
      case acmeObjOrderStatus ord of
        "processing" -> retry poll
        "valid" -> return ord
        s -> error $ "state not good: " ++ s

class CertificateForm a where
  fromBytestring :: B.ByteString -> a

instance CertificateForm X509.SignedCertificate where
  fromBytestring x =
    case X509.decodeSignedObject x of
      Left e -> error e
      Right v -> v

instance CertificateForm PEM where
  fromBytestring x =
    PEM
      "CERTIFICATE"
      []
      (X509.encodeSignedObject (fromBytestring x :: X509.SignedCertificate))

instance CertificateForm String where
  fromBytestring x = B.unpack $ pemWriteBS (fromBytestring x :: PEM)

retrieveCertificate :: CertificateForm a => AcmeObjOrder -> CragT [a]
retrieveCertificate o = do
  crts <-
    parsePEMBody <$>
    httpsGet (fromMaybe (error "no cert url") (acmeObjOrderCertificate o))
  return (map fromBytestring crts)

-- ** Authorization
-- | Get all authorizations of an order
acmePerformGetAuthorizations :: AcmeObjOrder -> CragT [AcmeObjAuthorization]
acmePerformGetAuthorizations =
  mapM acmePerformGetObject . acmeObjOrderAuthorizations

data ChallengeReaction = ChallengeReaction
  { fulfill :: AcmeObjIdentifier -> AcmeKeyAuthorization -> IO ()
  , rollback :: AcmeObjIdentifier -> AcmeKeyAuthorization -> IO ()
  }

acmePerformChallengeReaction ::
     [(String, ChallengeReaction)] -> [AcmeObjAuthorization] -> CragT ()
acmePerformChallengeReaction reactions authzs = do
  ops <- mapM findReaction authzs'
  sequence_
    [ do keyAuthz <- acmeKeyAuthorization challenge
         let identifier = acmeObjAuthorizationIdentifier authz
         liftIO $ fulfill reaction identifier keyAuthz
         acmeChallengeRespond challenge (rollback reaction identifier)
    | (authz, challenge, reaction) <- ops
    ]
  where
    authzs' = filter ((== "pending") . acmeObjAuthorizationStatus) authzs
    findReaction ::
         AcmeObjAuthorization
      -> CragT (AcmeObjAuthorization, AcmeObjChallenge, ChallengeReaction)
    findReaction authz =
      case listToMaybe
             [ (authz, challenge, reaction)
             | challenge <- acmeObjAuthorizationChallenges authz
             , (t, reaction) <- reactions
             , t == acmeObjChallengeType challenge
             ] of
        Just x -> return x
        Nothing ->
          throwError $ AcmeErrNoFullfillableChallenge (map fst reactions) authz

acmePerformFinalizeOrder :: AcmeObjOrder -> Base64Octets -> CragT AcmeObjOrder
acmePerformFinalizeOrder order =
  acmePerformFinalizeOrder' (acmeObjOrderFinalize order)

acmePerformFinalizeOrder' :: URL -> Base64Octets -> CragT AcmeObjOrder
acmePerformFinalizeOrder' url csr =
  resBody =<< httpsJwsPostUrl url (AcmeObjFinalizeOrder csr)

-- | Respond to challenge
acmeChallengeRespond ::
     AcmeObjChallenge
  -> (AcmeKeyAuthorization -> IO ())
  -> CragT AcmeObjChallenge
acmeChallengeRespond challenge cleanup = do
  k <- acmeKeyAuthorization challenge
  res <- resBody <$> httpsJwsPostUrl (acmeObjChallengeUrl challenge) emptyObject
  catchError res (handler k)
  where
    handler k e = do
      _ <- liftIO $ cleanup k
      throwError e

-- | Revoke
acmePerformRevokeCertificate :: AcmeObjRevokeCertificate -> CragT ()
acmePerformRevokeCertificate obj =
  void (httpsJwsPost AcmeDirectoryRequestRevokeCert obj)

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

-- | Get ACME Object
acmePerformGetObject :: FromJSON a => URL -> CragT a
acmePerformGetObject url = resBody =<< httpsGet url

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

retry :: CragT a -> CragT a
retry poll = do
  i <- asks (cragConfigPollingInterval . cragConfig)
  liftIO $ threadDelay (secondsToMicroseconds i)
  poll

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
