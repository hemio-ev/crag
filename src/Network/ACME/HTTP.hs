module Network.ACME.HTTP where

import Control.Monad.Trans.Except
import Crypto.JOSE
import Data.Aeson
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Foldable
import Network.HTTP.Simple
import Network.HTTP.Types
import Network.URI

import Network.ACME.Errors
import Network.ACME.JWS
import Network.ACME.Types

-- ** ACME Server Response
data AcmeResponse = AcmeResponse
  { acmeResponseHeaders :: Headers
  , acmeResponseBody :: L.ByteString
  } deriving (Show)

type Headers = [(HeaderName, B.ByteString)]

resHeader :: HeaderName -> AcmeResponse -> ExceptT RequestError IO String
resHeader x (AcmeResponse h _) =
  case find (\(n, _) -> n == x) h of
    Just (_, v) -> return $ B.unpack v
    Nothing -> throwE $ HeaderNotFound x

resHeaderAsURI :: HeaderName -> AcmeResponse -> ExceptT RequestError IO URI
resHeaderAsURI x ys = do
  h <- resHeader x ys
  case parseURI h of
    Just u -> return u
    Nothing -> throwE $ ResponseHeaderDecodeError (show x) h

resBody
  :: FromJSON a
  => AcmeResponse -> ExceptT RequestError IO a
resBody res =
  case eitherDecode (acmeResponseBody res) of
    Right x -> return x
    Left msg -> throwE $ DecodingError msg (show res)

-- ** Perform ACME Server Request
-- | Perform POST query
acmeHttpPost
  :: AcmeRequest a
  => a -- ^ Request
  -> JWS AcmeJwsHeader
  -> ExceptT RequestError IO AcmeResponse
acmeHttpPost req bod = do
  parseResult req (Just bod') =<<
    httpLBS (setRequestBodyLBS bod' $ newHttpRequest POST req)
  where
    bod' = encode $ toJSONflat bod

-- | Perform GET query
acmeHttpGet
  :: (AcmeRequest a)
  => a -- ^ Request
  -> ExceptT RequestError IO AcmeResponse
acmeHttpGet req = parseResult req Nothing =<< httpLBS (newHttpRequest GET req)

-- | Perform HEAD query
acmeHttpHead
  :: (AcmeRequest a)
  => a -- ^ Request
  -> ExceptT RequestError IO AcmeResponse
acmeHttpHead req = do
  res <- httpLBS (newHttpRequest HEAD req)
  parseResult req Nothing res

-- | Transforms abstract ACME to concrete HTTP request
newHttpRequest
  :: (AcmeRequest a)
  => StdMethod
  -> a -- ^ ACME Request
  -> Request
newHttpRequest meth acmeReq =
  setRequestMethod (renderStdMethod meth) $ (parseRequest_ url)
  where
    url = show (acmeRequestUrl acmeReq)

-- ** Utils
parseResult
  :: (AcmeRequest a)
  => a
  -> Maybe L.ByteString -- ^ Body
  -> Response L.ByteString
  -> ExceptT RequestError IO AcmeResponse
parseResult req bod res
  | isExpectedResponseStatus res req =
    return $ AcmeResponse (getResponseHeaders res) (getResponseBody res)
  | otherwise =
    throwE $
    case eitherDecode (getResponseBody res) of
      Right e -> RequestErrorDetail (show req) (getResponseStatus res) e bod
      Left msg ->
        ErrorDecodingError (getResponseStatus res) msg $
        L.unpack $ getResponseBody res
  where
    isExpectedResponseStatus r expected =
      getResponseStatus r == acmeRequestExpectedStatus expected
