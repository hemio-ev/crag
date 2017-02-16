module Main where

import Data.Aeson
import qualified Data.ByteString.Char8 as B
import Data.Maybe
import Data.Yaml (decodeFileEither)
import Data.Yaml.Pretty
import Network.URI
import Text.Groom

import Network.ACME

confUrl :: AcmeRequestDirectory
--confUrl =
--  fromJust $ decode "\"https://acme-staging.api.letsencrypt.org/directory\""
confUrl = fromJust $ decode "\"http://172.17.0.1:4000/directory\""

loadAccount :: FilePath -> IO AcmeObjAccount
loadAccount file = do
  d <- decodeFileEither file
  case d of
    Right x -> return x
    Left e -> error $ groom e

main :: IO ()
main = do
  acc <- newAcmeObjAccountStub "sophie_test_2@hemio.de"
  --putStrLn $ groom acc
  let directory = acmePerformDirectory (confUrl)
  _ <- handleError $ (directory >>= acmePerformNewAccount acc)
  _ <-
    handleError $
    (directory >>=
     acmePerformUpdateAccount
       (acc {acmeObjAccountAgreement = parseURI "http://boulder:4000/terms/v1"}))
  --putStrLn $ groom updatedAccount
  challenge <-
    handleError $
    (directory >>=
     acmePerformExistingAuthz (acmeNewDnsAuthz "hemev-test-1.xyz") acc)
  putStrLn $ groom challenge
  --challenge <- handleError $ (directory >>= acmePerformNewAuthz (acmeNewDnsAuthz "hemev-test-1.xyz") acc)
  --putStrLn $ groom challenge
  --let newApp = newAcmeObjOrder (Base64Octets $ Base64.decodeLenient csr)
  --appRes <- handleError $ (directory >>= acmePerformNewOrder newApp acc)
  --putStrLn $ groom appRes
  --regResult <- runExceptT $ (directory >>= acmePerformNewAccount acc)
  --putStrLn $ groom regResult
  return ()

--acc <- loadAccount "acc.yml"
--let jwk = fromKeyMaterial (acmeObjAccountKey acc)
---putStrLn $ toFp (acmeObjAccountKey acc)
--putStrLn $ jwkThumbprint (acmeObjAccountKey acc)
-- | Prints object in a pretty YAML form
jsonNice
  :: ToJSON a
  => a -> IO ()
jsonNice = B.putStrLn . encodePretty defConfig
