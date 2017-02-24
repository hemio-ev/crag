module T1 where

import Control.Concurrent
import Control.Monad.Trans.Except
import Crypto.Hash
import Crypto.PubKey.RSA
import Data.Aeson
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Maybe
import Data.X509
import Data.X509.PKCS10
import Network.ACME
import Network.HTTP.Simple
import Network.HTTP.Types
import Network.URI
import Test.Tasty
import Test.Tasty.HUnit

testAccToCert :: TestTree
testAccToCert =
  testCaseSteps "From new account to signed certificate" $ \step -> do
    let domain = "hemev-test-4.xyz" :: String
    step "acmePerformDirectory"
    directory <- assertExceptT $ acmePerformDirectory confUrl
    accStub <- acmeNewObjAccountStub "email@example.org"
    let acc =
          accStub
          {acmeObjAccountAgreement = parseURI "http://boulder:4000/terms/v1"}
    step "acmePerformAccountNew"
    _ <- assertExceptT $ acmePerformAccountNew acc directory
    step "acmePerformAuthorizationNew"
    authz <-
      assertExceptT $
      acmePerformAuthorizationNew (acmeNewDnsAuthz domain) acc directory
    challenge <- assertExceptT $ acmeGetPendingChallenge "dns-01" authz
    acmeObjChallengeType challenge @?= "dns-01"
    respHash <- assertExceptT $ acmeKeyAuthorization challenge acc
    step "setDnsTxt"
    _ <- setDnsTxt domain (sha256 respHash)
    step "acmePerformChallengeRespond"
    x <-
      assertExceptT $
      let response = AcmeObjChallengeResponse respHash
          req = acmeObjChallengeUri challenge
      in acmePerformChallengeRespond req response acc directory
    isJust (acmeObjChallengeKey_Authorization x) @?
      "keyAuthorization not accepted"
    step "(delay)"
    threadDelay (1 * 100000)
    csr <- newCrt domain
    step "acmePerformOrderNew"
    let cert = acmeNewObjOrder (Base64Octets csr)
    crt <- assertExceptT $ acmePerformOrderNew cert acc directory
    extensionGet (certExtensions $ getCertificate crt) @?=
      Just (ExtSubjectAltName [AltNameDNS domain])
    let revoke = acmeNewObjCertificateRevoke crt
    _ <- assertExceptT $ acmePerformCertificateRevoke revoke acc directory
    return ()

testAccount :: TestTree
testAccount =
  testCaseSteps "Account operations" $ \step -> do
    step "acmePerformDirectory"
    directory <- assertExceptT $ acmePerformDirectory confUrl
    step "acmePerformAccountNew"
    acc <- acmeNewObjAccountStub email1
    accReturned <- assertExceptT $ acmePerformAccountNew acc directory
    acmeObjAccountContact accReturned @?= acmeObjAccountContact acc
    step "acmePerformAccountURI"
    _ <- assertExceptT $ acmePerformAccountURI acc directory
    -- Update account
    step "acmePerformAccountUpdate (contact)"
    let acc' = acc {acmeObjAccountContact = Just ["mailto:" ++ email2]}
    accReturned' <- assertExceptT $ acmePerformAccountUpdate acc' directory
    acmeObjAccountContact accReturned' @?= acmeObjAccountContact acc'
    step "acmePerformAccountKeyRollover"
    accNew <- acmeNewObjAccountStub email1
    _ <- assertExceptT $ acmePerformAccountKeyRollover acc accNew directory
    --step "acmePerformAccountUpdate (status=deactivated)"
    --let acc'' = acc' {acmeObjAccountStatus = Just "deactivated"}
    --accReturned'' <- assertExceptT $ acmePerformAccountUpdate acc'' directory
    --acmeObjAccountStatus accReturned'' @?= Just "deactivated"
    --this should fail
    --_ <- assertExceptT $ acmePerformAccountUpdate acc directory
    --TODO: ASSERT FOR FAIL
    return ()
  where
    email1 = "email1@example.org" :: String
    email2 = "email2@example.org" :: String

newCrt :: String -> IO B.ByteString
newCrt domain = do
  let rsaKeySize = 256 :: Int
  let publicExponent = 0x10001 :: Integer
  (pubKey, privKey) <- generate rsaKeySize publicExponent
  let subjectAttrs =
        makeX520Attributes
          [(X520CommonName, domain), (X520OrganizationName, domain)]
  Right req <-
    generateCSR
      subjectAttrs
      (PKCS9Attributes [])
      (KeyPairRSA pubKey privKey)
      SHA512
  return $ toDER req

confUrl :: AcmeRequestDirectory
confUrl = fromJust $ decode "\"http://172.17.0.1:4000/directory\""

setDnsTxt :: String -> String -> IO (Response L.ByteString)
setDnsTxt hostName rdata = do
  res <- httpLBS req
  getResponseStatus res @?= status200
  return res
  where
    req =
      setRequestBodyLBS
        body
        (parseRequest_ "POST http://172.17.0.1:8055/set-txt")
    body =
      encode $
      object
        ["host" .= ("_acme-challenge." ++ hostName ++ "."), "value" .= rdata]

assertExceptT :: ExceptT AcmeErr IO a -> IO a
assertExceptT y =
  runExceptT y >>= \x ->
    case x of
      Right d -> return d
      Left e -> do
        assertFailure (showAcmeErr e)
        undefined
