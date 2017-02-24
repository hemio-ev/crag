module Network.ACME.HTTP where

import Control.Exception
import Control.Monad.Trans.Except
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

resHeader :: HeaderName -> AcmeResponse -> ExceptT AcmeErr IO String
resHeader x (AcmeResponse h _) =
  case find (\(n, _) -> n == x) h of
    Just (_, v) -> return $ B.unpack v
    Nothing -> throwE $ AcmeErrHeaderNotFound x

resHeaderAsURI :: HeaderName -> AcmeResponse -> ExceptT AcmeErr IO URI
resHeaderAsURI x ys = do
  h <- resHeader x ys
  case parseURI h of
    Just u -> return u
    Nothing ->
      throwE $
      AcmeErrDecodingHeader {acmeErrHeaderName = show x, acmeErrHeaderValue = h}

resBody
  :: FromJSON a
  => AcmeResponse -> ExceptT AcmeErr IO a
resBody res =
  case eitherDecode (acmeResponseBody res) of
    Right x -> return x
    Left msg ->
      throwE $
      AcmeErrDecodingBody {acmeErrMessage = msg, acmeErrBody = show res}

-- ** Perform ACME Server Request
-- | Perform POST query
acmeHttpPost
  :: AcmeRequest a
  => a -- ^ Request
  -> AcmeJws
  -> ExceptT AcmeErr IO AcmeResponse
acmeHttpPost req bod =
  parseResult req (Just bod') $
  httpLBS (setRequestBodyLBS bod' $ newHttpRequest POST req)
  where
    bod' = encode bod

-- | Perform GET query
acmeHttpGet
  :: (AcmeRequest a)
  => a -- ^ Request
  -> ExceptT AcmeErr IO AcmeResponse
acmeHttpGet req = parseResult req Nothing $ httpLBS (newHttpRequest GET req)

-- | Perform HEAD query
acmeHttpHead
  :: (AcmeRequest a)
  => a -- ^ Request
  -> ExceptT AcmeErr IO AcmeResponse
acmeHttpHead req = parseResult req Nothing $ httpLBS (newHttpRequest HEAD req)

-- | Transforms abstract ACME to concrete HTTP request
newHttpRequest
  :: (AcmeRequest a)
  => StdMethod
  -> a -- ^ ACME Request
  -> Request
newHttpRequest meth acmeReq =
  setRequestMethod (renderStdMethod meth) (parseRequest_ url)
  where
    url = show (acmeRequestUrl acmeReq)

-- ** Utils
parseResult
  :: (AcmeRequest a)
  => a
  -> Maybe L.ByteString -- ^ Body
  -> IO (Response L.ByteString)
  -> ExceptT AcmeErr IO AcmeResponse
parseResult req bod resIO =
  ExceptT $ do
    x <- try resIO
    return $
      case x of
        Left e -> Left $ AcmeErrHttp e
        Right res
          | isExpectedResponseStatus res req ->
            Right $ AcmeResponse (getResponseHeaders res) (getResponseBody res)
          | otherwise ->
            Left $
            case eitherDecode (getResponseBody res) of
              Right e ->
                AcmeErrDetail
                { acmeErrRequest = (show req)
                , acmeErrHttpStatus = (getResponseStatus res)
                , acmeErrProblemDetail = e
                , acmeErrRequestBody = bod
                }
              Left msg ->
                AcmeErrDecodingProblemDetail
                { acmeErrHttpStatus = getResponseStatus res
                , acmeErrMessage = msg
                , acmeErrResponseBody = L.unpack $ getResponseBody res
                }
  where
    isExpectedResponseStatus r expected =
      getResponseStatus r == acmeRequestExpectedStatus expected
