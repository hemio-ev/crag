module Main where

import Crypto.JOSE

import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Yaml.Pretty

import Data.Maybe

import Data.Aeson
import Data.Aeson.Types

import Network.ACME.JWS

import Network.HTTP.Simple
import Network.HTTP.Client (method)
import GHC.Generics

import Network.URI
import Network.HTTP.Types
import Network.Socket

import Data.Char
import Data.List

confUrl :: URI
confUrl =
  (fromJust $ decode "\"https://acme-staging.api.letsencrypt.org/directory\"")

main :: IO ()
main = do
  putStrLn "welcome"
  di <- acmePerformDirectory confUrl
  putStrLn $ show di
  acmePerformHeadNonce di >>= putStrLn

-- getResponseStatus x
-- ok200
-- created201
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
parseAcmeServerResponse
  :: (Generic a, GFromJSON Zero (Rep a))
  => String -> Value -> Parser a
parseAcmeServerResponse pre =
  genericParseJSON
    defaultOptions
    { fieldLabelModifier = f pre
    }
  where
    f pr str = foldr kebabKase "" (startLower withoutPrefix)
      where
        withoutPrefix =
          case stripPrefix pr str of
            Just x -> x
            Nothing -> error $ "JSON key " ++ str ++ " has no prefix " ++ pr
        startLower (x:xs) = toLower x : xs
        startLower [] = undefined
        kebabKase x y
          | isAsciiLower x = x : y
          | otherwise = '-' : toLower x : y

{-|
In order to help clients configure themselves with the right URIs for
each ACME operation, ACME servers provide a directory object.
-}
data AcmeDirectory = AcmeDirectory
  { acmeDirectoryNewNonce :: Maybe URI -- ^ New nonce
  , acmeDirectoryNewReg :: Maybe URI -- ^ New registration
  , acmeDirectoryNewApp :: Maybe URI -- ^ New application
  , acmeDirectoryNewAuthz :: Maybe URI -- ^ New authorization
  , acmeDirectoryRevokeCert :: Maybe URI -- ^ Revoke certificate
  , acmeDirectoryKeyChange :: Maybe URI -- ^ Key change
  , acmeDirectoryMeta :: Maybe AcmeDirectoryMeta
  , acmeDirectoryNewCert :: Maybe URI -- ^ Boulder's non-standard field
  } deriving (Show, Eq, Generic)

class AcmeOperation a  where
  operationUrl :: a -> URI
  operationHttpMethod :: a -> StdMethod

instance FromJSON AcmeDirectory where
  parseJSON = parseAcmeServerResponse "acmeDirectory"

data AcmeDirectoryMeta = AcmeDirectoryMeta
  { acmeDirectoryMetaTermsOfService :: Maybe URI
  , acmeDirectoryMetaWebsite :: Maybe URI
  , acmeDirectoryCaaIdentities :: Maybe [HostName]
  } deriving (Show, Eq, Generic)

instance FromJSON AcmeDirectoryMeta where
  parseJSON = parseAcmeServerResponse "acmeDirectoryMeta"

newAcmeRequest
  :: StdMethod -- ^ HTTP method
  -> URI
  -> Request
newAcmeRequest meth uri =
  (parseRequest_ $ show uri)
  { method = renderStdMethod meth
  }

checkResponseStatus :: Response a -> Status -> IO ()
checkResponseStatus r expected
  | getResponseStatus r == expected = return ()
  | otherwise = error "unexpected status"

acmePerformDirectory :: URI -> IO AcmeDirectory
acmePerformDirectory url = do
  res <- httpJSON (newAcmeRequest GET url)
  checkResponseStatus res ok200
  return $ getResponseBody res

acmePerformHeadNonce
  :: AcmeDirectory -- ^ URL config
  -> IO String -- ^ Nonce
acmePerformHeadNonce AcmeDirectory {..} = do
  let req = newAcmeRequest HEAD (fromJust acmeDirectoryNewReg)
  res <- httpNoBody req
  case getResponseHeader "Replay-Nonce" res of
    nonce:_ -> return $ B.unpack nonce
    [] -> error $ show req ++ " does not result in a 'Replay-Nonce': " ++ show res

generateKey :: IO KeyMaterial
generateKey = genKeyMaterial (ECGenParam P_256)

-- | Prints object in a pretty YAML form
jsonNice
  :: ToJSON a
  => a -> IO ()
jsonNice = B.putStrLn . encodePretty defConfig
