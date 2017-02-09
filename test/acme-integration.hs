{-# LANGUAGE TemplateHaskell #-}

module Main where

import Data.Aeson
import qualified Data.ByteString.Lazy.Char8 as L
import Data.FileEmbed
import Data.Maybe
import Test.Tasty
import Test.Tasty.HUnit

import Network.ACME
import T1

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Integration Tests" [integrationTests]

integrationTests :: TestTree
integrationTests = testGroup "Network.ACME" [completeUntiCert]
