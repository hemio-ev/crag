module TestIntegration
  ( integrationTests
  ) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.State (evalStateT)
import Crypto.Hash (SHA512(SHA512))
import Crypto.PubKey.RSA (generate)
import Data.Aeson (decode)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Maybe (fromJust)
import Data.PEM (pemWriteBS)
import Data.X509 (AltName(AltNameDNS), ExtSubjectAltName(ExtSubjectAltName))
import Data.X509.PKCS10
  ( KeyPair(KeyPairRSA)
  , PKCS9Attribute(PKCS9Attribute)
  , PKCS9Attributes(PKCS9Attributes)
  , X520Attribute(..)
  , generateCSR
  , makeX520Attributes
  , toDER
  , toPEM
  )
import Network.Connection (TLSSettings(TLSSettingsSimple))
import Network.HTTP.Client
  ( Manager
  , managerResponseTimeout
  , newManager
  , responseTimeoutMicro
  )
import Network.HTTP.Client.TLS (mkManagerSettings)
import Network.HTTP.Types
import Network.Wai (responseLBS)
import Network.Wai.Handler.Warp
import System.Process (spawnProcess, terminateProcess)
import Test.Tasty
import Test.Tasty.HUnit

import Network.ACME

pebbleResource :: TestTree -> TestTree
pebbleResource = withResource pebbleProcess terminateProcess . const
  where
    pebbleProcess = do
      p <- spawnProcess "gopath/bin/pebble" []
      -- TODO: wait for 'Pebble running'
      threadDelay (2 * 1000000)
      return p

integrationTests :: TestTree
integrationTests =
  pebbleResource $ testGroup "Network.ACME" [testNewAccount, testOrderNew]

myHttpServer :: String -> IO ()
myHttpServer x = run 5002 app
  where
    app _ respond = respond $ responseLBS status200 [] (L.pack x)

newUnsafeTestManager :: IO Manager
newUnsafeTestManager =
  newManager
    (mkManagerSettings (TLSSettingsSimple True False False) Nothing)
    {managerResponseTimeout = responseTimeoutMicro 3000000}

challengeResponders :: [(String, ChallengeResponder ())]
challengeResponders =
  [ ( "http-01"
    , \_ (AcmeKeyAuthorization auhtzkey) c -> do
        _ <- liftIO $ forkIO $ myHttpServer auhtzkey
        liftIO $ putStrLn "responded"
        -- submit challenge without rollback thing
        _ <- c $ return ()
        -- TODO: replace with polling
        liftIO $ threadDelay (10 * 1000000)
        liftIO $ putStrLn "submitted")
  ]

testOrderNew :: TestTree
testOrderNew =
  testCase "Handle error" $ do
    (accStub, jwk) <- acmeNewObjAccountStub "email@example.org"
    manager <- newUnsafeTestManager
    state <- acmePerformState' manager confUrl jwk
    flip evalStateT state $ do
      let domain = "localhost"
      csr <- liftIO $ newCrt domain
      let cert = Base64Octets csr
      _ <- acmePerformCreateAccount accStub
      objOrder <- acmePerformNewOrder (acmeNewObjOrder [domain])
      _ <-
        acmePerformGetAuthorizations objOrder >>=
        acmePerformChallengeResponses challengeResponders
      _ <- acmePerformFinalizeOrder objOrder cert
      return ()

testNewAccount :: TestTree
testNewAccount =
  testCase "Account operations" $ do
    (acc, jwk) <- acmeNewObjAccountStub "email1@example.org"
    manager <- newUnsafeTestManager
    state <- acmePerformState' manager confUrl jwk
    flip evalStateT state $ do
      _ <- acmePerformCreateAccount acc
      url <- acmePerformFindAccountURL
      liftIO $ print url
      return ()
    return ()

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
