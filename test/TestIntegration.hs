module TestIntegration
  ( integrationTests
  ) where

import Control.Concurrent (forkIO)
import Control.Monad.Except
import Control.Monad.IO.Class (liftIO)
import Crypto.Hash (SHA512(SHA512))
import Crypto.PubKey.RSA (generate)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Either (isRight)
import Data.IORef
import Data.List (isInfixOf)
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
import GHC.IO.Handle (hDuplicateTo, hGetLine)
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
import System.IO
import System.Process
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
  testCaseSteps "Account operations" $ \step -> do
    (acc, jwk) <- acmeNewObjAccountStub "email1@example.org"
    state <- myState jwk putStrLn
    _ <-
      flip evalCragT state $ do
        (url1, accObj) <- acmePerformCreateAccount acc
        url2 <- acmePerformFindAccountURL
        return (url1 @?= url2)
    return ()

testOrderNew :: TestTree
testOrderNew =
  testCaseSteps "testOrderNew" $ \step -> do
    (accStub, jwk) <- acmeNewObjAccountStub "email@example.org"
    httpServerLiveConf <- newIORef []
    _ <- forkIO $ myHttpServer httpServerLiveConf
    state <- myState jwk putStrLn
    res <-
      flip evalCragT state $ do
        let domains = ["localhost"] --, "ip6-localhost", "ip6-loopback"]
        csr <- liftIO $ newCrt domains
        let cert = Base64Octets csr
        _ <- acmePerformCreateAccount accStub
        crt <-
          obtainCertificate domains cert (challengeReactions httpServerLiveConf)
        liftIO $ putStrLn ("CRT: " <> concat crt)
        return ()
    print res
    isRight res @?= True

myState jwk step = do
  manager <- newUnsafeTestManager
  let logger x = step ("[cragLog] " <> x)
  (Right state) <-
    runExceptT $ acmePerformRunner' manager (Just logger) (config jwk)
  return state

challengeReactions :: HTTPServerLiveConf -> [(String, ChallengeReaction)]
challengeReactions httpServerLiveConf =
  [ ( http01
    , ChallengeReaction
        { fulfill =
            \identifier keyAuthz -> do
              addResponse
                (requestId identifier keyAuthz, keyAuthorization keyAuthz)
                httpServerLiveConf
              putStrLn "[Challenge Reaction] Fulfilled challenge"
        , rollback =
            \identifier keyAuthz -> do
              removeResponse (requestId identifier keyAuthz) httpServerLiveConf
              putStrLn "[Challenge Reaction] Removed challenge response"
        })
  ]
  where
    requestId identifier keyAuthz =
      (acmeObjIdentifierValue identifier, keyAuthorizationHttpPath keyAuthz)

pebbleResource :: TestTree -> TestTree
pebbleResource = withResource pebbleProcess terminateProcess . const
  where
    pebbleProcess = do
      stdOut <- openFile "pebble.log" WriteMode
      let pr =
            (proc "gopath/bin/pebble" ["-strict"]) {std_out = UseHandle stdOut}
      (_, _, _, pid) <- createProcess_ "spawnProcess" pr
      return pid

type HTTPServerLiveConf = IORef [((String, String), String)]

addResponse :: ((String, String), String) -> HTTPServerLiveConf -> IO ()
addResponse x httpServerLiveConf = modifyIORef httpServerLiveConf (x :)

removeResponse :: (String, String) -> HTTPServerLiveConf -> IO ()
removeResponse k httpServerLiveConf =
  modifyIORef httpServerLiveConf (filter ((/= k) . fst))

myHttpServer :: HTTPServerLiveConf -> IO ()
myHttpServer v = do
  runSettings (setHost "::1" $ setPort 5002 defaultSettings) app
  runSettings (setHost "127.0.0.1" $ setPort 5002 defaultSettings) app
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
          putStrLn $
            "[HTTP-Server] Responding to request: " ++ show (host, path)
          respond $ responseLBS status200 [] (L.pack r)

newUnsafeTestManager :: IO Manager
newUnsafeTestManager =
  newManager
    (mkManagerSettings (TLSSettingsSimple True False False) Nothing)
      {managerResponseTimeout = responseTimeoutMicro 3000000}

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
