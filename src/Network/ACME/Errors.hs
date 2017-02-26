module Network.ACME.Errors where

import Control.Monad.Trans.Except
import Crypto.JOSE
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Maybe
import Data.Typeable
import Data.Yaml.Pretty
import Network.HTTP.Client
import Network.HTTP.Types

import Network.ACME.Types

handleError :: ExceptT AcmeErr IO a -> IO a
handleError x = do
  res <- runExceptT x
  case res of
    Left e -> error $ "fatal:\n" ++ showAcmeErr e
    Right y -> return y

maybeToExceptT :: AcmeErr -> Maybe a -> ExceptT AcmeErr IO a
maybeToExceptT e Nothing = throwE e
maybeToExceptT _ (Just x) = return x

throwAcmeErrRequestNotSupported
  :: AcmeRequest a
  => Maybe a -> ExceptT AcmeErr IO b
throwAcmeErrRequestNotSupported x =
  throwE $ AcmeErrRequestNotSupported (show $ head $ typeRepArgs $ typeOf x)

data AcmeErr
  -- | Server reported an error with structured details
  = AcmeErrDetail { acmeErrRequest :: String
                 ,  acmeErrHttpStatus :: Status
                 ,  acmeErrProblemDetail :: ProblemDetail
                 ,  acmeErrRequestBody :: Maybe L.ByteString}
  -- | Wrapper for JWS Errors
  | AcmeErrJws Error
    -- | Wrapper for catched HTTP exceptions
  | AcmeErrHttp HttpException
  -- | Wanted challenge type to available
  | AcmeErrNoChallenge String
  -- | Challenge did not contain a "token" field
  | AcmeErrNoToken AcmeObjChallenge
  -- | Request not supported by the server (not in 'AcmeObjDirectory')
  | AcmeErrRequestNotSupported { acmeErrRequestType :: String}
  --
  -- API violations: The following errors should not occur
  --
  -- | Expected HTTP status but body has not the expected format
  | AcmeErrDecodingBody { acmeErrMessage :: String
                       ,  acmeErrBody :: String}
  -- | Unexpected HTTP response status, but response is not a 'ProblemDetail'
  | AcmeErrDecodingProblemDetail { acmeErrHttpStatus :: Status
                                ,  acmeErrMessage :: String
                                ,  acmeErrResponseBody :: String}
  -- | Header content could not be decoded
  | AcmeErrDecodingHeader { acmeErrHeaderName :: String
                         ,  acmeErrHeaderValue :: String}
  -- | Certificate could not be decoded
  | AcmeErrDecodingX509 { acmeErrMessage :: String
                       ,  acmeErrBody :: String}
  -- | Expected HTTP header not found
  | AcmeErrHeaderNotFound HeaderName
  deriving (Show)

showAcmeErr :: AcmeErr -> String
showAcmeErr AcmeErrDetail {..} =
  "Request: " ++
  acmeErrRequest ++
  "\nStatus: " ++
  showStatus acmeErrHttpStatus ++
  "\n\nDetails:\n" ++
  B.unpack (encodePretty defConfig acmeErrProblemDetail) ++
  "\nRequest Body:\n" ++ L.unpack (fromMaybe "EMPTY" acmeErrRequestBody)
showAcmeErr (AcmeErrDecodingBody msg original) =
  "The response body could not be decoded\nerror: " ++
  msg ++ "\nbody:\n" ++ original
showAcmeErr x = show x

showStatus :: Status -> String
showStatus Status {..} = show statusCode ++ " " ++ B.unpack statusMessage

acmeErrD :: AcmeErr -> Maybe ProblemDetail
acmeErrD AcmeErrDetail {..} = Just acmeErrProblemDetail
acmeErrD _ = Nothing
