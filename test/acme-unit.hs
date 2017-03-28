{-# LANGUAGE TemplateHaskell #-}

module Main where

import Data.Aeson
import qualified Data.ByteString.Lazy.Char8 as L
import Data.FileEmbed
import Data.Maybe
import Test.Tasty
import Test.Tasty.HUnit

import Network.ACME

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Unit Tests" [unitTests]

unitTests :: TestTree
unitTests =
  testGroup
    "Network.ACME.JWS"
    [ testCase "jwkThumbprint (rfc7638-jwk.json example)" $
      let file = $(embedStringFile "test/rfc7638-jwk.json") :: L.ByteString
          jwk' = fromJust (decode file) :: JWK
      in jwkThumbprint jwk' @?= "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    ]
