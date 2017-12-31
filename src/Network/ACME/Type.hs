module Network.ACME.Type where

import Control.Monad.Reader (ReaderT, runReaderT)
import Control.Monad.State (StateT, runStateT)
import Crypto.JOSE (JWK)
import Network.HTTP.Client (Manager)

import Network.ACME.Object

-- ** Monad Transformer
type CragT = StateT CragState (ReaderT CragReader IO)

runCragT :: CragT a -> (CragReader, CragState) -> IO (a, CragState)
runCragT x (r, s) = (`runReaderT` r) $ (`runStateT` s) x

evalCragT :: CragT a -> (CragReader, CragState) -> IO a
evalCragT x v = do
  (o, _) <- runCragT x v
  return o

-- ** Client Configuration
data CragConfig = CragConfig
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
data CragState = CragState
  { cragStateDirectory :: AcmeObjDirectory
  , cragStateNonce :: Maybe AcmeJwsNonce
  , cragStateKid :: Maybe URL
  }

data CragReader = CragReader
  { cragConfig :: CragConfig
  , cragSetup :: CragSetup
  }

data CragSetup = CragSetup
  { cragSetupJwkPublic :: JWK
  , cragSetupHttpManager :: Manager
  }
