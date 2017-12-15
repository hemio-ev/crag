module Network.ACME
  ( module Network.ACME
  , module X
  ) where

import Control.Exception.Lifted (throw, try)
import Control.Monad (msum, void)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Class
import Control.Monad.Trans.State (gets)
import Network.Socket (HostName)

--import Control.Monad.Trans.Except
--import Control.Monad.Trans.State
import Crypto.JOSE (KeyMaterialGenParam(RSAGenParam), genJWK)

--import Data.Aeson
import Data.Aeson.Types (emptyObject)

--import qualified Data.ByteString.Lazy.Char8 as L
import Data.Foldable
import Data.Maybe
import qualified Data.X509 as X509
import Network.HTTP.Client (Manager) -- defaultManagerSettings
import Network.HTTP.Client.TLS (newTlsManager)

import Network.ACME.Errors as X
import Network.ACME.HTTP
import Network.ACME.JWS as X
import Network.ACME.Types as X

-- * Perform Requests
-- ** Directory
acmePerformState :: URL -> JWK -> IO AcmeState
acmePerformState vUrl vJwk = do
  manager <- newTlsManager
  acmePerformState' manager vUrl vJwk

acmePerformState' :: Manager -> URL -> JWK -> IO AcmeState
acmePerformState' manager vUrl vJwk = do
  res <- acmePerformDirectory vUrl manager
  return
    AcmeState
    { acmeStateDirectory = res
    , acmeStateNonce = Nothing
    , acmeStateJwkPrivate = vJwk
    , acmeStateJwkPublic = jwkPublic vJwk
    , acmeStateKid = Nothing
    , acmeStateHttpManager = manager
    }

-- ** Account
-- | Registeres new account
acmePerformAccountNew :: AcmeObjStubAccount -> AcmeT AcmeObjAccount
acmePerformAccountNew stubAcc =
  resBody <$> acmeHttpJwsPostNewAccount AcmeDirectoryRequestNewAccount stubAcc

-- | Recover the account uri
acmePerformAccountUrl :: AcmeT URL
acmePerformAccountUrl = do
  res <- acmeHttpJwsPostNewAccount AcmeDirectoryRequestNewAccount emptyObject
  lift $ resHeaderAsURI "Location" res

-- | Update account
acmePerformAccountUpdate :: AcmeObjAccount -> AcmeT AcmeObjAccount
acmePerformAccountUpdate newAcc = do
  url <- acmePerformAccountUrl
  resBody <$> acmeHttpJwsPostUrl url newAcc

-- | Key Roll-over
acmePerformAccountKeyRollover ::
     JWK -- ^ Account with current key
  -> JWK -- ^ Same account with new key
  -> AcmeT AcmeObjAccount
acmePerformAccountKeyRollover current _
  --accUrl <- acmePerformAccountUrl
  --let objRollover = AcmeObjAccountKeyRollover (jwkPublic new) (Just accUrl)
  --innerJws <- return current -- acmeNewJwsBody req objRollover new
 = do
  let innerJws = current
  resBody <$> acmeHttpJwsPost AcmeDirectoryRequestKeyChange innerJws

-- ** Certificate
-- | Create new application (handing in a certificate request)
acmePerformOrderNew :: AcmeObjOrder -> AcmeT AcmeObjOrderStatus
acmePerformOrderNew ord =
  resBody <$> acmeHttpJwsPost AcmeDirectoryRequestNewOrder ord
  -- :: X509.SignedCertificate

{-  
  return $ decodeCert $ getResponseBody res
  where
    decodeCert b =
      case X509.decodeSignedCertificate (L.toStrict b) of
        Right c -> c
        Left e -> throw (AcmeErrDecodingX509 e (show b))
-}
-- ** Authorization
acmePerformAuthorizationGet :: URL -> AcmeT AcmeObjAuthorization
acmePerformAuthorizationGet url = resBody <$> acmeHttpGet url

type ChallengeResponder a
   = HostName -> AcmeKeyAuthorization -> (IO () -> AcmeT AcmeObjChallenge) -- ^ Perform challenge response, first argument is rollback
                                          -> AcmeT a

acmePerformChallengeResponses ::
     [(String, ChallengeResponder a)]
  -> [AcmeObjAuthorization]
  -> AcmeT [a] -- ^ 
acmePerformChallengeResponses fs as = do
  let actions =
        map getF (filter ((== "pending") . acmeObjAuthorizationStatus) as)
  mapM apply actions
  where
    cs :: AcmeObjAuthorization -> [(String, AcmeObjChallenge)]
    cs a =
      map (\x -> (acmeObjChallengeType x, x)) $ acmeObjAuthorizationChallenges a
    --g :: AcmeObjAuthorization -> Maybe (String -> String -> IO a, AcmeObjChallenge)
    g a = msum [(,) f . (,) a <$> lookup chType (cs a) | (chType, f) <- fs]
    getF a =
      fromMaybe (throw $ AcmeErrNoFullfillableChallenge (map fst fs) a) (g a)
    apply (f, (a, ch)) = do
      argKey <- acmeKeyAuthorization ch
      let argId = acmeObjIdentifierValue (acmeObjAuthorizationIdentifier a)
          authz = acmeChallengeRespond (acmeObjChallengeUrl ch) argKey
      f argId argKey authz

acmePerformFinalize :: URL -> Base64Octets -> AcmeT AcmeObjOrderStatus
acmePerformFinalize url csr =
  resBody <$> acmeHttpJwsPostUrl url (AcmeObjFinalize csr)

{-
-- | New authorization
acmePerformAuthorizationNew ::
     AcmeObjAuthorizationNew -> AcmeT AcmeObjAuthorization
acmePerformAuthorizationNew authz =
  resBody <$> acmeHttpJwsPost AcmeDirectoryRequestNewAuthz authz
-}
-- | Respond to challenge
acmeChallengeRespond ::
     URL -> AcmeKeyAuthorization -> IO () -> AcmeT AcmeObjChallenge
acmeChallengeRespond req k cleanup = do
  res <- try $ resBody <$> acmeHttpJwsPostUrl req (AcmeObjChallengeResponse k)
  case res of
    Right r -> return r
    Left e -> do
      _ <- liftIO cleanup
      throw (e :: AcmeErr)

acmeChallengeRespond' :: URL -> AcmeKeyAuthorization -> AcmeT AcmeObjChallenge
acmeChallengeRespond' req k = acmeChallengeRespond req k (return ())

-- | Revoke
acmePerformCertificateRevoke :: AcmeObjCertificateRevoke -> AcmeT ()
acmePerformCertificateRevoke obj =
  void (acmeHttpJwsPost AcmeDirectoryRequestRevokeCert obj)

-- * Utils
-- ** Object generation
acmeNewObjAccountStub :: String -> IO (AcmeObjStubAccount, JWK)
acmeNewObjAccountStub mail = do
  keyMat <- genJWK (RSAGenParam 256)
  return
    ( AcmeObjStubAccount
      { acmeObjStubAccountContact = Just ["mailto:" ++ mail]
      , acmeObjStubAccountTermsOfServiceAgreed = Just True
      , acmeObjStubAccountOnlyReturnExisting = Nothing
      }
    , keyMat)

acmeNewObjOrder :: [String] -> AcmeObjOrder
acmeNewObjOrder xs =
  AcmeObjOrder
  { acmeObjOrderIdentifiers = map toId xs
  , acmeObjOrderNotBefore = Nothing
  , acmeObjOrderNotAfter = Nothing
  }
  where
    toId v =
      AcmeObjIdentifier
      {acmeObjIdentifierType = "dns", acmeObjIdentifierValue = v}

acmeNewObjCertificateRevoke ::
     X509.SignedCertificate -> AcmeObjCertificateRevoke
acmeNewObjCertificateRevoke crt =
  AcmeObjCertificateRevoke
  { acmeObjCertificateRevokeCertificate =
      Base64Octets (X509.encodeSignedObject crt)
  , acmeObjCertificateRevokeReason = Nothing
  }

-- ** Object inquiry 
acmeGetPendingChallenge ::
     String -- ^ Type
  -> AcmeObjAuthorization
  -> AcmeObjChallenge
acmeGetPendingChallenge t =
  fromMaybe (throw $ AcmeErrNoChallenge t) . acmeMaybePendingChallenge t

acmeMaybePendingChallenge ::
     String -- ^ Type
  -> AcmeObjAuthorization
  -> Maybe AcmeObjChallenge
acmeMaybePendingChallenge t authz =
  find cond (acmeObjAuthorizationChallenges authz)
  where
    cond x =
      acmeObjChallengeStatus x == "pending" && acmeObjChallengeType x == t

-- ** Other
acmeKeyAuthorization :: AcmeObjChallenge -> AcmeT AcmeKeyAuthorization
acmeKeyAuthorization ch = do
  jwk <- gets acmeStateJwkPublic
  return . AcmeKeyAuthorization $ acmeKeyAuthorization' ch jwk

acmeKeyAuthorization' :: AcmeObjChallenge -> JWK -> String
acmeKeyAuthorization' ch acc =
  acmeObjChallengeToken ch ++ "." ++ jwkThumbprint acc
