module Main where

import Test.Tasty

import T1

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Integration Tests" [integrationTests]

integrationTests :: TestTree
integrationTests = testGroup "Network.ACME" [testAccToCert, testAccount]
