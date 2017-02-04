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
import Data.Yaml (decodeFileEither)

import Network.ACME.JWS
import Network.ACME.Types
import Network.ACME.Internal

import Control.Monad.Trans.Except

confUrl :: AcmeRequestDirectory
confUrl =
  (fromJust $ decode "\"https://acme-staging.api.letsencrypt.org/directory\"")

loadAccount :: FilePath -> IO AcmeAccount
loadAccount x = do
  Right d <- decodeFileEither x
  return d

main :: IO ()
main = do
  acc <- loadAccount "acc.yml"
  putStrLn $ show acc

  let direct = acmePerformDirectory (confUrl)
  let obj = AcmeObjNewReg ["mailto:sophie_test_1@hemio.de"]

  regResult <- runExceptT $ (direct >>= acmePerformNewReg acc)
  putStrLn $ show regResult
  
  return ()

newJwsObj ::
   (AcmeRequest a, ToJSON o)
  => a
  -> o
  -> AcmeAccount
  -> AcmeDirectory
  -> ExceptT RequestError IO (JWS AcmeJwsHeader)
newJwsObj req obj acc dir = do
  nonce <- acmePerformNonce dir
  RequestJwsError `withExceptT` jwsSigned obj (acmeRequestUrl req) (acmeAccountKey acc) nonce

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
  { acmeAccountKey :: KeyMaterial,
  acmeAccountContact :: [String]
  } deriving (Show, Eq, Generic)

instance FromJSON AcmeAccount where
  parseJSON = parseAcmeServerResponse "acmeAccount"
instance ToJSON AcmeAccount where
  toJSON = toAcmeConfigStore "acmeAccount"
  
  
data AcmeObjNewReg = AcmeObjNewReg {
  acmeObjNewRegContact :: [String]
  } deriving (Show, Eq, Generic)
  
instance ToJSON AcmeObjNewReg where
  toJSON = toAcmeRequestBody "acmeObjNewReg"

-------------------------------
----- ENGINE
-- | Transforms abstract ACME to concrete HTTP request
newHttpRequest
  :: (AcmeRequest a)
  => StdMethod
  -> a -- ^ ACME Request
  -> Request
newHttpRequest meth acmeReq =
  setRequestMethod (renderStdMethod meth) $ (parseRequest_ url)
  where
    url = show (acmeRequestUrl acmeReq)

acmeHttpPost
  :: (AcmeRequest a, FromJSON c)
  => a -- ^ Request
  -> JWS AcmeJwsHeader
  -> ExceptT RequestError IO c
acmeHttpPost req bod = do
  parseJsonResult req =<<
    httpLBS (setRequestBodyLBS (encode $ toJSONflat bod) $ newHttpRequest POST req)

acmeHttpGet
  :: (AcmeRequest a, FromJSON b)
  => a -- ^ Request
  -> ExceptT RequestError IO b
acmeHttpGet req = parseJsonResult req =<< httpLBS (newHttpRequest GET req)

parseJsonResult
  :: (AcmeRequest a, FromJSON b)
  => a -> Response L.ByteString -> ExceptT RequestError IO b
parseJsonResult req res
  | expectedResponseStatus res req =
    return $ (fromJust $ decode $ getResponseBody res)
  | otherwise =
    throwE $
    RequestErrorDetail
      (getResponseStatus res)
      (fromJust $ decode $ getResponseBody res)

-- | Perform HTTP query
acmeHttpHead
  :: (AcmeRequest a)
  => a -- ^ Request
  -> ExceptT RequestError IO (Response ())
acmeHttpHead req = do
  res <- httpNoBody (newHttpRequest HEAD req)
  if expectedResponseStatus res req
      then return res
      else throwE $ RequestErrorStatus (getResponseStatus res)

expectedResponseStatus
  :: (AcmeRequest b)
  => Response a -> b -> Bool
expectedResponseStatus r expected =
  getResponseStatus r == acmeRequestExpectedStatus expected

-- requestBodyJSON :: a -> Request -> Request
data RequestError
  = RequestErrorDetail Status
                       ProblemDetail
  | RequestErrorStatus Status
  | RequestJwsError Error
  deriving (Show)

----- PERFORM
acmePerformNonce
  :: AcmeDirectory -- ^ URL config
  -> ExceptT RequestError IO AcmeJwsNonce -- ^ Nonce
acmePerformNonce d = do
  f <$> acmeHttpHead req
 where 
  f res =
        case getResponseHeader "Replay-Nonce" res of
          nonce:_ -> AcmeJwsNonce $ B.unpack nonce
          [] ->
            error $ show req ++ " does not result in a 'Replay-Nonce': " ++ show res
  
  req = acmeGuessNewNonceRequest d

-- | Fallback to directory url, since Boulder does not implement /new-nonce/
acmeGuessNewNonceRequest :: AcmeDirectory -> AcmeRequestNewNonce
acmeGuessNewNonceRequest AcmeDirectory {..} =
  case acmeDirectoryNewNonce of
    Just x -> x
    Nothing -> AcmeRequestNewNonce (acmeRequestUrl $ fromJust acmeDirectory)

-- | Get all supported resources from server
acmePerformDirectory :: AcmeRequestDirectory -> ExceptT RequestError IO AcmeDirectory
acmePerformDirectory acmeReq = addDirectory <$> acmeHttpGet acmeReq
  where
    addDirectory x =
      x
      { acmeDirectory = Just acmeReq
      }

acmePerformNewReg :: AcmeAccount -> AcmeDirectory -> ExceptT RequestError IO AcmeAccount
acmePerformNewReg acc dir =
  newJwsObj req acc acc dir >>= acmeHttpPost req
 where
  req = fromJust $ acmeDirectoryNewReg dir

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
