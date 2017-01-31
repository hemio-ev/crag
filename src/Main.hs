module Main where

import Crypto.JOSE
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Yaml.Pretty
import Data.Maybe
import Data.Aeson
import Data.Aeson.Types
import Network.HTTP.Simple
import Network.HTTP.Client (method)
import GHC.Generics
import Network.URI
import Network.HTTP.Types

import Network.ACME.JWS
import Network.ACME.Types
import Network.ACME.Internal

confUrl :: AcmeRequestDirectory
confUrl =
  (fromJust $ decode "\"https://acme-staging.api.letsencrypt.org/directory\"")

main :: IO ()
main = do
  putStrLn "welcome"
  di <- acmePerformDirectory (confUrl)
  --putStrLn $ show di
  acmePerformHeadNonce di >>= putStrLn

main2 :: IO ()
main2 = do
  let jwsContent =
        newJWS
          "{\
\       \"agreement\": \"https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf\",\
\       \"resource\": \"new-reg\",\
\       \"contact\": [\
\         \"mailto:sophie_test_1@hemio.de\"\
\       ]\
\     }"
  key1 <- generateKey
  jsonNice key1
  signed <- signWith jwsContent key1
  L.writeFile "post.json" (encode $ toJSONflat signed)
  return ()

data AcmeServerResponse
  = AcmeServerError { detail :: String}
  | AcmeServerReg { agreement :: String}
  deriving (Eq, Show, Generic)

instance FromJSON AcmeServerResponse where
  parseJSON =
    genericParseJSON
      (defaultOptions
       { sumEncoding = UntaggedValue
       })

------------------
-----------
data AcmeAccount = AcmeAccount
  { acmeAccountKey :: KeyMaterial
  }

-------------------------------
newHttpRequest
  :: AcmeRequest a
  => a -> Request
newHttpRequest acmeReq =
  (parseRequest_ $ show (acmeRequestUrl acmeReq))
  { method = renderStdMethod (acmeRequestHttpMethod acmeReq)
  }

acmeGuessNewNonceRequest :: AcmeDirectory -> AcmeRequestNewNonce
acmeGuessNewNonceRequest AcmeDirectory {..} =
  case acmeDirectoryNewNonce of
    Just x -> x
    Nothing -> AcmeRequestNewNonce (acmeRequestUrl $ fromJust acmeDirectory)

checkResponseStatus_
  :: (AcmeRequest b)
  => Response a -> b -> IO ()
checkResponseStatus_ r expected
  | getResponseStatus r == acmeRequestExpectedStatus expected = return ()
  | otherwise =
    error $
    "Unexpected status for " ++
    show expected ++ " got " ++ show (getResponseStatus r)

httpQuery
  :: (AcmeRequest b)
  => (Request -> IO (Response a0)) -> b -> IO (Response a0)
httpQuery f req = do
  res <- f (newHttpRequest req)
  checkResponseStatus_ res req
  return res

acmePerformDirectory :: AcmeRequestDirectory -> IO AcmeDirectory
acmePerformDirectory acmeReq = do
  res <- httpQuery httpJSON acmeReq
  let d = getResponseBody res
  return
    (d
     { acmeDirectory = Just acmeReq
     })

acmePerformHeadNonce
  :: AcmeDirectory -- ^ URL config
  -> IO String -- ^ Nonce
acmePerformHeadNonce d = do
  res <- httpQuery httpNoBody req
  case getResponseHeader "Replay-Nonce" res of
    nonce:_ -> return $ B.unpack nonce
    [] -> error $ show req ++ " does not result in a 'Replay-Nonce': " ++ show res
  where
    req = acmeGuessNewNonceRequest d

generateKey :: IO KeyMaterial
generateKey = genKeyMaterial (ECGenParam P_256)

-- | Prints object in a pretty YAML form
jsonNice
  :: ToJSON a
  => a -> IO ()
jsonNice = B.putStrLn . encodePretty defConfig
