{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Crypto.JOSE.JWS
import Crypto.JOSE.Types
import Crypto.JOSE.JWK
import Crypto.JOSE.Error
import Crypto.JOSE

import Data.Maybe
import Control.Monad.Except
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Yaml.Pretty

import Data.Aeson
import Data.Monoid ((<>))
import GHC.Exts (fromList)

import Control.Lens (preview)

main :: IO ()
main = do 
  let jwsContent = newJWS "{\
\       \"agreement\": \"https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf\",\
\       \"resource\": \"new-reg\",\
\       \"contact\": [\
\         \"mailto:sophie_test_1@hemio.de\"\
\       ]\
\     }"

  key1 <- generateKey
  key2 <- generateKey
  
  jsonNice key1
  
  signed <- signWith jwsContent key1
  L.writeFile "post.json" (encode $ toFlatJSON signed)

  return ()

generateKey :: IO KeyMaterial
generateKey = genKeyMaterial (ECGenParam P_256)

toFlatJSON (JWS p (s:[])) = Object $
    toObject s <>
    fromList ["payload" .= p]
toFlatJSON (JWS _ _) = undefined

toObject :: ToJSON a => a -> Object
toObject a = case toJSON a of
  Object o -> o
  _        -> error "toObject: value isn't an Object"

jsonNice = B.putStrLn . encodePretty defConfig

signWith jwsContent keyMat = do
      signed <- runExceptT $ signJWS jwsContent header jwkPrivate
  
      return $ case signed of
                Left (e :: Error) -> error $ show $ e
                Right jwsSign -> jwsSign
  where
    header = (newJWSHeader (Unprotected, ES256)) {
      _jwsHeaderJwk = Just $ HeaderParam Unprotected jwkPublic }
      
    jwkPrivate :: JWK
    jwkPrivate = fromKeyMaterial keyMat
    jwkPublic :: JWK
    jwkPublic =  fromJust $ preview asPublicKey jwkPrivate

very x y = do
  y <- runExceptT $ verifyJWS defaultValidationSettings x y
  
  return $ case y of
            Left (e :: Error) -> error $ show $ e
            Right x' -> x'
