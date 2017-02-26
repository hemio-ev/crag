module Main where

import Test.Tasty

import TestIntegration

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Integration Tests" [integrationTests]
