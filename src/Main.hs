module Main where

import Crypto.JOSE
import Data.Aeson
import Data.Maybe
import Data.Yaml.Pretty
import qualified Data.ByteString.Char8 as B
import Data.Yaml (decodeFileEither)
import Control.Monad.Trans.Except

import Network.ACME

confUrl :: AcmeRequestDirectory
--confUrl =
--  fromJust $ decode "\"https://acme-staging.api.letsencrypt.org/directory\""
confUrl = fromJust $ decode "\"http://172.17.0.1:4000/directory\""

loadAccount :: FilePath -> IO AcmeAccount
loadAccount file = do
  d <- decodeFileEither file
  case d of
    Right x -> return x
    Left e -> error $ show e

main :: IO ()
main = do
  acc <- loadAccount "acc.yml"
  --putStrLn $ show acc
  let direct = acmePerformDirectory (confUrl)
  --let obj = AcmeObjNewReg ["mailto:sophie_test_1@hemio.de"]
  let newApp = newAcmeObjNewApp "BLA"
  appRes <- runExceptT $ (direct >>= acmePerformNewApp newApp acc)
  putStrLn $ show appRes
  --regResult <- runExceptT $ (direct >>= acmePerformNewReg acc)
  --putStrLn $ show regResult
  return ()

generateKey :: IO KeyMaterial
generateKey = genKeyMaterial (ECGenParam P_256)

-- | Prints object in a pretty YAML form
jsonNice
  :: ToJSON a
  => a -> IO ()
jsonNice = B.putStrLn . encodePretty defConfig
