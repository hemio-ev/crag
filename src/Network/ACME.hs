module Network.ACME
  ( module Network.ACME
  , module X
  ) where

import Control.Exception.Lifted (throw, try)
import Control.Monad (msum, void)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Class
import Control.Monad.Trans.State (gets)
import Crypto.JOSE (KeyMaterialGenParam(RSAGenParam), genJWK)
import Data.Default.Class (def)
import Network.Socket (HostName)

--import Data.Aeson.Types (emptyObject)
--import Data.Foldable
import Data.Maybe
import qualified Data.X509 as X509
import Network.HTTP.Client (Manager) -- defaultManagerSettings
import Network.HTTP.Client.TLS (newTlsManager)

import Network.ACME.Errors as X
import Network.ACME.HTTP
import Network.ACME.JWS as X
import Network.ACME.Object as X
import Network.ACME.Type

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
-- | Account Creation (Registration)
acmePerformCreateAccount :: AcmeObjStubAccount -> AcmeT AcmeObjAccount
acmePerformCreateAccount stubAcc =
  resBody <$> acmeHttpJwsPostNewAccount AcmeDirectoryRequestNewAccount stubAcc

-- | Finding an Account URL Given a Key
acmePerformFindAccountURL :: AcmeT URL
acmePerformFindAccountURL = do
  res <-
    acmeHttpJwsPostNewAccount
      AcmeDirectoryRequestNewAccount
      def {acmeObjStubAccountOnlyReturnExisting = Just True}
  lift $ resHeaderAsURL "Location" res

-- | Account Update
acmePerformUpdateAccount :: AcmeObjAccount -> AcmeT AcmeObjAccount
acmePerformUpdateAccount newAcc = do
  url <- acmePerformFindAccountURL
  resBody <$> acmeHttpJwsPostUrl url newAcc

-- | Key Roll-over
acmePerformAccountKeyRollover ::
     JWK -- ^ Account with current key
  -> JWK -- ^ Same account with new key
  -> AcmeT AcmeObjAccount
acmePerformAccountKeyRollover current _
  --accUrl <- acmePerformFindAccountURL
  --let objRollover = AcmeObjAccountKeyRollover (jwkPublic new) (Just accUrl)
  --innerJws <- return current -- acmeNewJwsBody req objRollover new
 = do
  let innerJws = current
  resBody <$> acmeHttpJwsPost AcmeDirectoryRequestKeyChange innerJws

-- ** Certificate
-- | Create new application (handing in a certificate request)
acmePerformNewOrder :: AcmeObjNewOrder -> AcmeT AcmeObjOrder
acmePerformNewOrder ord =
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
acmePerformGetAuthorizations :: AcmeObjOrder -> AcmeT [AcmeObjAuthorization]
acmePerformGetAuthorizations =
  mapM acmePerformGetAuthorization . acmeObjOrderAuthorizations

acmePerformGetAuthorization :: URL -> AcmeT AcmeObjAuthorization
acmePerformGetAuthorization url = resBody <$> acmeHttpGet url

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

acmePerformFinalizeOrder :: AcmeObjOrder -> Base64Octets -> AcmeT AcmeObjOrder
acmePerformFinalizeOrder order =
  acmePerformFinalizeOrder' (acmeObjOrderFinalize order)

acmePerformFinalizeOrder' :: URL -> Base64Octets -> AcmeT AcmeObjOrder
acmePerformFinalizeOrder' url csr =
  resBody <$> acmeHttpJwsPostUrl url (AcmeObjFinalizeOrder csr)

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
acmePerformRevokeCertificate :: AcmeObjRevokeCertificate -> AcmeT ()
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

{-
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
-}
-- ** Other
-- | keyAuthorization for a given challenge
acmeKeyAuthorization :: AcmeObjChallenge -> AcmeT AcmeKeyAuthorization
acmeKeyAuthorization ch = do
  jwk <- gets acmeStateJwkPublic
  return . AcmeKeyAuthorization $ acmeKeyAuthorization' ch jwk

acmeKeyAuthorization' :: AcmeObjChallenge -> JWK -> String
acmeKeyAuthorization' ch acc =
  acmeObjChallengeToken ch ++ "." ++ jwkThumbprint acc
