module T1 where

import Control.Concurrent
import Control.Monad.Trans.Except
import Crypto.Hash
import Crypto.PubKey.RSA
import Data.Aeson
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Maybe
import Data.PEM
import Data.X509
import Data.X509.PKCS10
import Network.ACME
import Network.ACME.JWS
import Network.HTTP.Simple
import Network.HTTP.Types
import Network.URI
import Test.Tasty
import Test.Tasty.HUnit

crt :: String -> IO B.ByteString
crt domain = do
  let rsaKeySize = 256
  let publicExponent = 0x10001
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
  return $ toDER req -- export in PEM format

confUrl :: AcmeRequestDirectory
confUrl = fromJust $ decode "\"http://172.17.0.1:4000/directory\""

setDnsTxt :: String -> String -> IO (Response L.ByteString)
setDnsTxt hostName hash = do
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
        ["host" .= ("_acme-challenge." ++ hostName ++ "."), "value" .= hash]

completeUntiCert :: TestTree
completeUntiCert =
  testCaseSteps "Complete until certificate" $ \step -> do
    let domain = "hemev-test-1.xyz" :: String
    step "acmePerformDirectory"
    directory <- assertExceptT $ acmePerformDirectory confUrl
    accStub <- (newAcmeObjAccountStub "sophie_test_2@hemio.de")
    let acc =
          accStub
          {acmeObjAccountAgreement = parseURI "http://boulder:4000/terms/v1"}
    step "acmePerformNewAccount"
    accReturned <- assertExceptT $ acmePerformNewAccount acc directory
    step "acmePerformNewAuthz"
    authz <-
      assertExceptT $ acmePerformNewAuthz (acmeNewDnsAuthz domain) acc directory
    challenge <- assertExceptT $ acmeGetPendingChallenge "dns-01" authz
    acmeObjChallengeType challenge @?= "dns-01"
    hash <- assertExceptT $ acmeKeyAuthorization challenge acc
    step "acmePerformRespondChallenge"
    x <-
      assertExceptT $
      let response = AcmeObjChallengeResponse hash
          req = acmeObjChallengeUri challenge
      in acmePerformRespondChallenge req response acc directory
    isJust (acmeObjChallengeKey_Authorization x) @?
      "keyAuthorization not accepted"
    step "setDnsTxt"
    _ <- setDnsTxt domain (sha256 hash)
    step "Wait an order certificate"
    threadDelay (10 * 1000000)
    csr <- crt domain
    let cert = newAcmeObjOrder (Base64Octets csr)
    _ <- assertExceptT $ acmePerformNewOrder cert acc directory
    step "Done."

assertExceptT :: ExceptT RequestError IO a -> IO a
assertExceptT y =
  runExceptT y >>= \x ->
    case x of
      Right d -> return d
      Left e -> do
        assertFailure (showRequestError e)
        undefined
