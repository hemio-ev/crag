module TestIntegration
  ( integrationTests
  ) where

import Control.Concurrent
import Control.Monad
import Control.Monad.IO.Class

import Control.Exception

--import Control.Monad.Trans.Class
--import Control.Monad.Trans.Except
import Control.Monad.Trans.State
import Crypto.Hash
import Crypto.PubKey.RSA
import Data.Aeson
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Default (def)
import Data.Maybe
import Data.X509
import Data.X509.PKCS10
import Network.Connection -- (settingDisableCertificateValidation)
import Network.HTTP.Client
  ( managerResponseTimeout
  , newManager
  , responseTimeoutMicro
  )
import Network.HTTP.Client.TLS (mkManagerSettings)
import Network.HTTP.Simple
import Network.HTTP.Types
import Network.URI
import Test.Tasty
import Test.Tasty.HUnit
import Data.PEM

import Network.ACME
import Network.ACME.Errors

integrationTests :: TestTree
integrationTests = testGroup "Network.ACME" [testAccount, testOrderNew] --[testAccount, testFail]

prettyHandle :: IO a -> IO a
prettyHandle = handle handler
  where
    handler :: SomeException -> IO a
    handler = error . displayException

newUnsafeTestManager =
  newManager
    (mkManagerSettings (TLSSettingsSimple True False False) Nothing)
    {managerResponseTimeout = responseTimeoutMicro 3000000}

challengeResponders =
  [ ( "dns-01"
    , \a b c -> do
        liftIO $ putStrLn "responded"
        _ <- c $ return ()
        liftIO $ putStrLn "submitted")
  ]

testOrderNew :: TestTree
testOrderNew =
  testCase "Handle error" $
  prettyHandle $ do
    (accStub, jwk) <- acmeNewObjAccountStub "email@example.org"
    manager <- newUnsafeTestManager
    state <- acmePerformState' manager confUrl jwk
    flip evalStateT state $ do
      _ <- acmePerformAccountNew accStub
      csr <- liftIO $ newCrt "abc.hemev-test-16.xyz"
      let cert = Base64Octets csr
      orderStatus <-
        acmePerformOrderNew $ acmeNewObjOrder ["abc.hemev-test-16.xyz"]
      liftIO $ print orderStatus
      auths <-
        mapM acmePerformAuthorizationGet $
        acmeObjOrderStatusAuthorizations orderStatus
      liftIO $ print auths
      mips <- acmePerformChallengeResponses challengeResponders auths
      liftIO $ print mips
      rrr <- acmePerformFinalize (acmeObjOrderStatusFinalize orderStatus) cert
      liftIO $ print rrr
      --keyau <-
      --  mapM acmeKeyAuthorization $ acmeObjAuthorizationChallenges (head auths)
      --liftIO $ print keyau
        -- Left e <- runExceptT $ 
        -- (acmeErrD e >>= problemDetailType) @?= parseURI "urn:acme:error:malformed"
      liftIO $ print "ende"

testAccount :: TestTree
testAccount =
  testCase "Account operations" $
  prettyHandle $
      --step "Nr. X"
   do
    (acc, jwk) <- acmeNewObjAccountStub "email1@example.org"
    manager <- newUnsafeTestManager
    state <- acmePerformState' manager confUrl jwk
    --liftIO $ step "acmePerformAccountNew"
    flip evalStateT state $ do
      accReturned <- acmePerformAccountNew acc
        --liftIO $ acmeObjAccountContact accReturned @?= acmeObjAccountContact acc
        --liftIO $ step "acmePerformAccountUrl"
      url <- acmePerformAccountUrl
      liftIO $ print url
      return ()
    return ()

{-
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
    step "acmePerformCertificateRevoke"
    let revoke = acmeNewObjCertificateRevoke crt
    _ <- assertExceptT $ acmePerformCertificateRevoke revoke acc directory
    return ()
-}
{-
testAccount2 :: TestTree
testAccount2 =
  testCaseSteps "Account operations" $ \step ->
    prettyHandle $
    void $
    assertExceptT $ do
      step "Nr. 1"
      (acc, jwk) <- acmeNewObjAccountStub email1
      state <- acmePerformState confUrl jwk
      flip evalStateT state $ do
        liftIO $ step "acmePerformAccountNew"
        accReturned <- acmePerformAccountNew acc
        liftIO $ acmeObjAccountContact accReturned @?= acmeObjAccountContact acc
        liftIO $ step "acmePerformAccountUrl"
        _ <- acmePerformAccountUrl acc
        -- Update account
        liftIO $ step "acmePerformAccountUpdate (contact)"
        let acc' = acc {acmeObjStubAccountContact = Just ["mailto:" ++ email2]}
        accReturned' <- acmePerformAccountUpdate acc'
        liftIO $
          acmeObjAccountContact accReturned' @?= acmeObjStubAccountContact acc'
        return accReturned'
        --liftIO $ step "acmePerformAccountKeyRollover"
        --accNew <- liftIO $ acmeNewObjAccountStub email1
        --acmePerformAccountKeyRollover acc accNew
            --liftIO $ step "acmePerformAccountUpdate (status=deactivated)"
            --let acc'' = acc' {acmeObjAccountStatus = Just "deactivated"}
            --accReturned'' <- assertExceptT $ acmePerformAccountUpdate acc'' directory
            --acmeObjAccountStatus accReturned'' @?= Just "deactivated"
            --this should fail
            --_ <- assertExceptT $ acmePerformAccountUpdate acc directory
            --TODO: ASSERT FOR FAIL
            --return ()
  where
    email1 = "email1@example.org" :: String
    email2 = "email2@example.org" :: String
-}
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
      (PKCS9Attributes [PKCS9Attribute (ExtSubjectAltName [AltNameDNS domain])])
      (KeyPairRSA pubKey privKey)
      SHA512
  putStrLn $ B.unpack $ pemWriteBS $ toPEM req
  return $ toDER req

confUrl :: URL
confUrl = fromJust $ decode "\"https://localhost:14000/dir\""

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

assertExceptT :: IO a -> IO a
assertExceptT y = y -- catch exceptions
