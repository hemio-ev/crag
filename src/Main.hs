module Main where

import Crypto.JOSE

import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Yaml.Pretty

import Data.Aeson

import Network.ACME.JWS

import Network.HTTP.Simple
import Network.HTTP.Client (method)

main :: IO ()
main = do
  putStrLn "welcome"
  acmePerformHeadNonce
    "https://acme-staging.api.letsencrypt.org/acme/"
    "new-reg" >>=
    putStrLn

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

acmePerformHeadNonce
  :: String -- ^ URL config
  -> String -- ^ Task
  -> IO String -- ^ Nonce
acmePerformHeadNonce u t = do
  req <- parseRequest (u ++ t)
  res <-
    httpNoBody
      (req
       { method = "HEAD"
       })
  case (getResponseHeader "Replay-Nonce" res :: [B.ByteString]) of
    nonce:_ -> return $ B.unpack nonce
    [] -> error $ "Request " ++ show req ++ " did not return a nonce " ++ show res

generateKey :: IO KeyMaterial
generateKey = genKeyMaterial (ECGenParam P_256)

-- | Prints object in a pretty YAML form
jsonNice
  :: ToJSON a
  => a -> IO ()
jsonNice = B.putStrLn . encodePretty defConfig
