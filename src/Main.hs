module Main where

import Crypto.JOSE
import Crypto.JOSE.Types
import Data.Aeson
import Data.Maybe
import Data.Yaml.Pretty
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import qualified Data.ByteString.Base64.URL as Base64
import Data.Yaml (decodeFileEither)
import Control.Monad.Trans.Except
import Network.URI

--import Data.Byteable
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
    Left e -> error $ show e

main :: IO ()
main = do
  acc <- loadAccount "acc.yml"
  --let jwk = fromKeyMaterial (acmeObjAccountKey acc)
  ---putStrLn $ toFp (acmeObjAccountKey acc)
  putStrLn $ jwkThumbprint (acmeObjAccountKey acc)
  --acc <- newAcmeObjAccountStub "sophie_test_2@hemio.de"
  --putStrLn $ show acc
  let directory = acmePerformDirectory (confUrl)
  --_ <- handleError $ (directory >>= acmePerformNewAccount acc)
  _ <-
    handleError $
    (directory >>=
     acmePerformUpdateAccount
       (acc
        { acmeObjAccountAgreement = parseURI "http://boulder:4000/terms/v1"
        }))
  --putStrLn $ show updatedAccount
  challenge <-
    handleError $
    (directory >>=
     acmePerformExistingAuthz (acmeNewDnsAuthz "hemev-test-1.xyz") acc)
  putStrLn $ show challenge
  --challenge <- handleError $ (directory >>= acmePerformNewAuthz (acmeNewDnsAuthz "hemev-test-1.xyz") acc)
  --putStrLn $ show challenge
  --let newApp = newAcmeObjOrder (Base64Octets $ Base64.decodeLenient csr)
  --appRes <- handleError $ (directory >>= acmePerformNewOrder newApp acc)
  --putStrLn $ show appRes
  --regResult <- runExceptT $ (directory >>= acmePerformNewAccount acc)
  --putStrLn $ show regResult
  return ()

handleError :: ExceptT RequestError IO a -> IO a
handleError x = do
  res <- runExceptT x
  case res of
    Left e -> error $ "fatal:\n" ++ showRequestError e
    Right y -> return y

generateKey :: IO KeyMaterial
generateKey = genKeyMaterial (ECGenParam P_256)

-- | Prints object in a pretty YAML form
jsonNice
  :: ToJSON a
  => a -> IO ()
jsonNice = B.putStrLn . encodePretty defConfig

newAcmeObjAccountStub :: String -> IO AcmeObjAccount
newAcmeObjAccountStub mail = do
  keyMat <- genKeyMaterial (ECGenParam P_256)
  return $
    AcmeObjAccount
    { acmeObjAccountKey = keyMat
    , acmeObjAccountContact = Just ["mailto:" ++ mail]
    , acmeObjAccountStatus = Nothing
    , acmeObjAccountTermsOfServiceAgreed = Nothing
    , acmeObjAccountOrders = Nothing
    , acmeObjAccountAgreement = Nothing
    }
