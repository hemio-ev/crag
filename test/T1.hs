module T1 where

import Crypto.JOSE
import Data.Aeson
import Data.Aeson.Types (emptyObject)
import Data.Maybe
import Network.HTTP.Simple
import Network.HTTP.Types
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Control.Monad.Trans.Except
import Network.URI
import Data.Yaml.Pretty

import Network.ACME

ff :: String -> String -> ExceptT RequestError IO (Response L.ByteString)
ff hostName hash = do
  x <- httpLBS req
  return x 
 where 
  req = setRequestBodyLBS body (parseRequest_ "POST http://172.17.0.1:8055/set-txt")  
  body = encode $ object [ "host" .= hostName,
      "value".= hash]

xxx :: AcmeRequestDirectory -> IO AcmeObjChallenge
xxx url = do
  directory <- handleError $ acmePerformDirectory url
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
  --putStrLn $ show chal
  
  x <-
    handleError $
    do hash <- acmeKeyAuthorization chal acc
       o <- ff "_acme-challenge.hemev-test-2.xyz." (sha256 $ L.pack hash)
       let chalResp = AcmeObjChallengeResponse hash
       acmePerformRespondChallenge (acmeObjChallengeUri chal) chalResp acc directory
  --putStrLn $ show x
  return x
  
