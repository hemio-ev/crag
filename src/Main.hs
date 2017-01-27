{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Crypto.JOSE

import Control.Monad.Except
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Yaml.Pretty

import Data.Aeson


import Network.ACME.JWS

main :: IO ()
main = do
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

generateKey :: IO KeyMaterial
generateKey = genKeyMaterial (ECGenParam P_256)

jsonNice :: ToJSON a => a -> IO ()
jsonNice = B.putStrLn . encodePretty defConfig

signWith :: 
                  JWS AcmeJwsHeader -> KeyMaterial -> IO (JWS AcmeJwsHeader)

signWith jwsContent keyMat = do
  signed <- runExceptT $ signJWS jwsContent header' jwk
  return $
    case signed of
      Left (e :: Error) -> error $ show e
      Right jwsSign -> jwsSign
  where
    header' = newAcmeJwsHeader jwk
    jwk = fromKeyMaterial keyMat

