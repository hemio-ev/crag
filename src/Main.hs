module Main where

import Crypto.JOSE
import Data.Aeson
import Data.Aeson.Types
import Data.Maybe
import Data.Yaml.Pretty
import GHC.Generics
import Network.HTTP.Client (method)
import Network.HTTP.Simple
import Network.HTTP.Types
import Network.URI
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L

import Network.ACME.JWS
import Network.ACME.Types
import Network.ACME.Internal

import Control.Monad.Trans.Except

confUrl :: AcmeRequestDirectory
confUrl =
  (fromJust $ decode "\"https://acme-staging.api.letsencrypt.org/directory\"")

eR (Right x) = x

main :: IO ()
main = do
  di <- acmePerformDirectory (confUrl)
  nonce <- acmePerformNonce $ eR di
  let jwsContent =
        newJWS
          "{\
\       \"agreement\": \"https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf\",\
\       \"resource\": \"https://acme-staging.api.letsencrypt.org/acme/new-reg\",\
\       \"contact\": [\
\         \"mailto:sophie_test_1@hemio.de\"\
\       ]\
\     }"
  key1 <- generateKey
  jsonNice key1
  signed <- signWith jwsContent key1 nonce
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

----- ENGINE



-- | Transforms abstract ACME to concrete HTTP request
newHttpRequest
  :: (AcmeRequest a)
  => StdMethod
  -> a -- ^ ACME Request
  -> Request
newHttpRequest meth acmeReq = setRequestMethod (renderStdMethod meth) $
  (parseRequest_  url)
 where 
  url =   show (acmeRequestUrl acmeReq)
  

acmeHttpPost
  :: (AcmeRequest a, ToJSON b, FromJSON c)
  => a -- ^ Request
  -> b
  -> IO (Either (Status, Maybe ProblemDetail) c)
acmeHttpPost req bod = do
  parseJsonResult req <$> httpLBS (setRequestBodyJSON bod $ newHttpRequest POST req)

acmeHttpGet
  :: (AcmeRequest a, FromJSON b)
  => a -- ^ Request
  -> IO (Either (Status, Maybe ProblemDetail) b)
acmeHttpGet req = parseJsonResult req <$> httpLBS (newHttpRequest GET req)
      
parseJsonResult :: (AcmeRequest a, FromJSON b)
  => a -> Response L.ByteString -> Either (Status, Maybe ProblemDetail) b
parseJsonResult req res
 | expectedResponseStatus res req = Right (fromJust $ decode $ getResponseBody res)
 | otherwise = Left (getResponseStatus res, fromJust $ decode $ getResponseBody res)

-- | Perform HTTP query
acmeHttpHead
  :: (AcmeRequest a)
  => a -- ^ Request
  -> IO (Either Status (Response ()))
acmeHttpHead req = do
  res <- httpNoBody (newHttpRequest HEAD req)
  return $
    if expectedResponseStatus res req then
      Right res
    else
      Left (getResponseStatus res)

expectedResponseStatus
  :: (AcmeRequest b)
  => Response a -> b -> Bool
expectedResponseStatus r expected = getResponseStatus r == acmeRequestExpectedStatus expected

-- requestBodyJSON :: a -> Request -> Request

data RequestError = A | B deriving (Show)



----- PERFORM

acmePerformNonce
  :: AcmeDirectory -- ^ URL config
  -> IO AcmeJwsNonce -- ^ Nonce
acmePerformNonce d = do
  res' <- acmeHttpHead req
  case res' of
   (Right res) ->
    case getResponseHeader "Replay-Nonce" res of
      nonce:_ -> return $ AcmeJwsNonce $ B.unpack nonce
      [] -> error $ show req ++ " does not result in a 'Replay-Nonce': " ++ show res
 where
      req = acmeGuessNewNonceRequest d

-- | Fallback to directory url, since Boulder does not implement /new-nonce/
acmeGuessNewNonceRequest :: AcmeDirectory -> AcmeRequestNewNonce
acmeGuessNewNonceRequest AcmeDirectory {..} =
  case acmeDirectoryNewNonce of
    Just x -> x
    Nothing -> AcmeRequestNewNonce (acmeRequestUrl $ fromJust acmeDirectory)

-- | Get all supported resources from server
acmePerformDirectory :: AcmeRequestDirectory -> IO (Either (Status, Maybe ProblemDetail) AcmeDirectory)
acmePerformDirectory acmeReq = do
  res <- acmeHttpGet acmeReq
  return $ (\x -> x { acmeDirectory = Just acmeReq }) <$> res




------------------------ STUFF -------------------------
------------------------ STUFF -------------------------
------------------------ STUFF -------------------------
------------------------ STUFF -------------------------
------------------------ STUFF -------------------------


generateKey :: IO KeyMaterial
generateKey = genKeyMaterial (ECGenParam P_256)

-- | Prints object in a pretty YAML form
jsonNice
  :: ToJSON a
  => a -> IO ()
jsonNice = B.putStrLn . encodePretty defConfig


