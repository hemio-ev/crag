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

loadJwk :: IO KeyMaterial
loadJwk = do
  f <- decodeFileEither "rfc7638.jwk"
  case f of
    Left e -> error $ groom e
    Right x -> return x

main :: IO ()
main = do
  jwk <- loadJwk
  if jwkThumbprint jwk == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    then putStrLn "Test passed."
    else error "Unit test failed."
  directory <- handleError $ acmePerformDirectory confUrl
  accStub <- (newAcmeObjAccountStub "sophie_test_2@hemio.de")
  let acc =
        accStub
        { acmeObjAccountAgreement = parseURI "http://boulder:4000/terms/v1"
        }
  _ <- handleError $ acmePerformNewAccount acc directory
  challenge <-
    handleError $ acmePerformNewAuthz (acmeNewDnsAuthz "hemev-test-2.xyz") acc directory
  --putStrLn $ groom challenge
  let chal = (acmeObjAuthorizationChallenges challenge) !! 0
  putStrLn $ groom chal
  x <-
    handleError $
    do hash <- acmeKeyAuthorization chal acc
       let chalResp = AcmeObjChallengeResponse hash
       acmePerformRespondChallenge (acmeObjChallengeUri chal) chalResp acc directory
  putStrLn $ groom x
  return ()

main2 :: IO ()
main2
--acc <- loadAccount "acc.yml"
--let jwk = fromKeyMaterial (acmeObjAccountKey acc)
---putStrLn $ toFp (acmeObjAccountKey acc)
--putStrLn $ jwkThumbprint (acmeObjAccountKey acc)
 = do
  acc <- newAcmeObjAccountStub "sophie_test_2@hemio.de"
  --putStrLn $ groom acc
  let directory = acmePerformDirectory (confUrl)
  _ <- handleError $ (directory >>= acmePerformNewAccount acc)
  _ <-
    handleError $
    (directory >>=
     acmePerformUpdateAccount
       (acc
        { acmeObjAccountAgreement = parseURI "http://boulder:4000/terms/v1"
        }))
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

handleError :: ExceptT RequestError IO a -> IO a
handleError x = do
  res <- runExceptT x
  case res of
    Left e -> error $ "fatal:\n" ++ showRequestError e
    Right y -> return y

acmeKeyAuthorization :: AcmeObjChallenge
                     -> AcmeObjAccount
                     -> ExceptT RequestError IO String
acmeKeyAuthorization ch acc =
  case acmeObjChallengeToken ch of
    Nothing -> throwE $ AcmeErrNoToken ch
    Just token -> return $ token ++ "." ++ jwkThumbprint (acmeObjAccountKey acc)

-- | Prints object in a pretty YAML form
jsonNice
  :: ToJSON a
  => a -> IO ()
jsonNice = B.putStrLn . encodePretty defConfig

newAcmeObjAccountStub :: String -> IO AcmeObjAccount
newAcmeObjAccountStub mail = do
  keyMat <- genKeyMaterial (RSAGenParam 256)
  return $
    AcmeObjAccount
    { acmeObjAccountKey = keyMat
    , acmeObjAccountContact = Just ["mailto:" ++ mail]
    , acmeObjAccountStatus = Nothing
    , acmeObjAccountTermsOfServiceAgreed = Nothing
    , acmeObjAccountOrders = Nothing
    , acmeObjAccountAgreement = Nothing
    }
