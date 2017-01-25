{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Crypto.JOSE.JWS
import Crypto.JOSE.Types
import Crypto.JOSE.JWK
import Crypto.JOSE.Error

import Data.Maybe
import Control.Monad.Except


main :: IO ()
main = do 
  let jwsContent = newJWS "Content Text"
  let header = newJWSHeader (Unprotected, RS256)

  jwk1 <- genJWK (RSAGenParam 512)
  jwk2 <- genJWK (RSAGenParam 512)
  
  signed <- runExceptT $ signJWS jwsContent header jwk1
  
  let x = case signed of
            Left (e :: Error) -> error $ show $ e
            Right jwsSign -> jwsSign
            
  putStrLn $ show x
  
  (show <$> very jwk1 x) >>= putStrLn
  (show <$> very jwk2 x) >>= putStrLn
  
  putStrLn "By."


very x y = do
  y <- runExceptT $ verifyJWS defaultValidationSettings x y
  
  return $ case y of
            Left (e :: Error) -> error $ show $ e
            Right x' -> x'
