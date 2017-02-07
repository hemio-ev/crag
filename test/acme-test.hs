{-# LANGUAGE TemplateHaskell #-}

module Main where

import Data.Aeson
import Data.Maybe
import Test.Tasty
--import Test.Tasty.SmallCheck as SC
--import Test.Tasty.QuickCheck as QC
import Test.Tasty.HUnit
import Data.FileEmbed
import qualified Data.ByteString.Lazy.Char8 as L

import Network.ACME
import T1


confUrl :: AcmeRequestDirectory
--confUrl =
--  fromJust $ decode "\"https://acme-staging.api.letsencrypt.org/directory\""
confUrl = fromJust $ decode "\"http://172.17.0.1:4000/directory\""

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [unitTests,integrationTests]

unitTests :: TestTree
unitTests =
  testGroup
    "Network.ACME.JWS"
    [ testCase "jwkThumbprint (rfc7638.jwk example)" $
      let 
        file = $(embedStringFile "test/rfc7638-jwk.json") :: L.ByteString
        jwk = fromJust (decode file) :: KeyMaterial
      in jwkThumbprint jwk @?= "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    ]

integrationTests :: TestTree
integrationTests =
  testCaseSteps "Get Auhtz" $ \step -> do
     step "1."
     res <- xxx confUrl

     isJust (acmeObjChallengeKey_Authorization res) @? "keyAuthorization not accepted"

