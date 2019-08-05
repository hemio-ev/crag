module Network.ACME.Type where

import Control.Monad.Except
import Control.Monad.Reader (ReaderT, asks, runReaderT)
import Control.Monad.State (StateT, runStateT)
import Crypto.JOSE (JWK)
import Network.HTTP.Client (Manager)

import Network.ACME.Error
import Network.ACME.Internal
import Network.ACME.Object

-- ** Monad Transformer
type CragT = StateT CragState (ReaderT CragReader (ExceptT AcmeErr IO))

runCragT ::
     CragT a -> (CragReader, CragState) -> IO (Either AcmeErr (a, CragState))
runCragT x (r, s) = runExceptT $ (`runReaderT` r) $ (`runStateT` s) x

evalCragT :: CragT a -> (CragReader, CragState) -> IO (Either AcmeErr a)
evalCragT x v = do
  o <- runCragT x v
  return (fst <$> o)

-- ** Client Configuration
data CragConfig =
  CragConfig
    { cragConfigDirectoryURL :: URL
    , cragConfigJwk :: JWK
    , cragConfigPollingInterval :: Int
  -- ^ Default polling interval in seconds.
  --
  -- If available, the servers @Retry-After@ header is used instead.
    , cragConfigRateLimitRetryAfter :: Int
  -- ^ Default retry interval in seconds when hitting rate limits.
  --
  -- If available, the servers @Retry-After@ header is used instead.
    }

-- ** State and Reader
data CragState =
  CragState
    { cragStateDirectory :: AcmeObjDirectory
    , cragStateNonce :: Maybe AcmeJwsNonce
    , cragStateKid :: Maybe URL
    }

data CragReader =
  CragReader
    { cragConfig :: CragConfig
    , cragSetup :: CragSetup
    }

data CragSetup =
  CragSetup
    { cragSetupJwkPublic :: JWK
    , cragSetupHttpManager :: Manager
    , cragSetupLogger :: CragLogger
    }

cragLog :: String -> CragT ()
cragLog msg = do
  logger <- asks (cragSetupLogger . cragSetup)
  liftIO $ cragLog' logger msg

cragLog' :: CragLogger -> String -> IO ()
cragLog' logger msg =
  case logger of
    Nothing -> return ()
    Just f -> liftIO $ f msg

type CragLogger = Maybe (String -> IO ())

deriveAcmeJSON ''CragConfig
