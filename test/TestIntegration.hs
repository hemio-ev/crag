module TestIntegration
  ( integrationTests
  ) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Monad.IO.Class (liftIO)
import Crypto.Hash (SHA512(SHA512))
import Crypto.PubKey.RSA (generate)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Either (isRight)
import Data.IORef
import Data.Maybe (fromJust, fromMaybe)
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
import Network.Wai (rawPathInfo, requestHeaders, responseLBS)
import Network.Wai.Handler.Warp
import System.Process (spawnProcess, terminateProcess)
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.JOSE.Types (Base64Octets(..))
import Network.ACME
import Network.ACME.Object
import Network.ACME.Type

integrationTests :: TestTree
integrationTests =
  pebbleResource $ testGroup "Network.ACME" [testNewAccount, testOrderNew]

testNewAccount :: TestTree
testNewAccount =
  testCase "Account operations" $ do
    (acc, jwk) <- acmeNewObjAccountStub "email1@example.org"
    manager <- newUnsafeTestManager
    state <- acmePerformRunner' manager (config jwk)
    flip evalCragT state $ do
      _ <- acmePerformCreateAccount acc
      url <- acmePerformFindAccountURL
      liftIO $ print url
      return ()
    return ()

testOrderNew :: TestTree
testOrderNew =
  testCase "Handle error" $ do
    (accStub, jwk) <- acmeNewObjAccountStub "email@example.org"
    httpServerLiveConf <- newIORef []
    _ <- forkIO $ myHttpServer httpServerLiveConf
    manager <- newUnsafeTestManager
    state <- acmePerformRunner' manager (config jwk)
    res <-
      flip evalCragT state $ do
        let domains = ["localhost"] --, "ip6-localhost", "ip6-loopback"]
        csr <- liftIO $ newCrt domains
        let cert = Base64Octets csr
        _ <- acmePerformCreateAccount accStub
        crt <-
          obtainCertificate domains cert (challengeReactions httpServerLiveConf)
        liftIO $ putStrLn (concat crt :: String)
        return ()
    isRight res @?= True

pebbleResource :: TestTree -> TestTree
pebbleResource = withResource pebbleProcess terminateProcess . const
  where
    pebbleProcess = do
      p <- spawnProcess "gopath/bin/pebble" []
      -- TODO: wait for 'Pebble running'
      threadDelay (2 * 1000000)
      return p

type HTTPServerLiveConf = IORef [((String, String), String)]

addResponse :: ((String, String), String) -> HTTPServerLiveConf -> IO ()
addResponse x httpServerLiveConf = modifyIORef httpServerLiveConf (x :)

removeResponse :: (String, String) -> HTTPServerLiveConf -> IO ()
removeResponse k httpServerLiveConf =
  modifyIORef httpServerLiveConf (filter ((/= k) . fst))

myHttpServer :: HTTPServerLiveConf -> IO ()
myHttpServer v = runSettings (setHost "::1" $ setPort 5002 defaultSettings) app
  where
    app req respond = do
      resp <- readIORef v
      let host =
            takeWhile (/= ':') $
            B.unpack $ fromJust $ lookup "Host" $ requestHeaders req
          path = B.unpack $ rawPathInfo req
      case lookup (host, path) resp of
        Nothing -> error $ show (host, path) ++ " not found in " ++ show resp
        Just r -> do
          putStrLn "responding NOW"
          print (host, path)
          respond $ responseLBS status200 [] (L.pack r)

newUnsafeTestManager :: IO Manager
newUnsafeTestManager =
  newManager
    (mkManagerSettings (TLSSettingsSimple True False False) Nothing)
      {managerResponseTimeout = responseTimeoutMicro 3000000}

challengeReactions :: HTTPServerLiveConf -> [(String, ChallengeReaction)]
challengeReactions httpServerLiveConf =
  [ ( http01
    , ChallengeReaction
        { fulfill =
            \identifier keyAuthz -> do
              addResponse
                (requestId identifier keyAuthz, keyAuthorization keyAuthz)
                httpServerLiveConf
              putStrLn "responded"
        , rollback =
            \identifier keyAuthz -> do
              removeResponse (requestId identifier keyAuthz) httpServerLiveConf
              putStrLn "removed"
        })
  ]
  where
    requestId identifier keyAuthz =
      (acmeObjIdentifierValue identifier, keyAuthorizationHttpPath keyAuthz)

newCrt :: [String] -> IO B.ByteString
newCrt domains = do
  let rsaKeySize = 256 :: Int
  let publicExponent = 0x10001 :: Integer
  (pubKey, privKey) <- generate rsaKeySize publicExponent
  let subjectAttrs =
        makeX520Attributes
          [(X520CommonName, head domains), (X520OrganizationName, head domains)]
  Right req <-
    generateCSR
      subjectAttrs
      (PKCS9Attributes
         [PKCS9Attribute . ExtSubjectAltName $ map AltNameDNS domains])
      (KeyPairRSA pubKey privKey)
      SHA512
  putStrLn $ B.unpack $ pemWriteBS $ toPEM req
  return $ toDER req

confUrl :: URL
confUrl =
  fromMaybe (error "invalid conf url") $ parseURL "https://localhost:14000/dir"

config jwk =
  CragConfig
    { cragConfigDirectoryURL = confUrl
    , cragConfigJwk = jwk
    , cragConfigPollingInterval = 2
    , cragConfigRateLimitRetryAfter = 2
    }
