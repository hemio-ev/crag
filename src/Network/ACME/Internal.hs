module Network.ACME.Internal where

import Crypto.JOSE.Types ()
import Data.Aeson
import Data.Aeson.TH (deriveJSON)
import Data.Char
import Data.List
import Language.Haskell.TH.Syntax (Dec, Name, Q, nameBase)
import Network.URI (URI, uriScheme)

deriveAcmeJSON :: Name -> Q [Dec]
deriveAcmeJSON n = deriveJSON (acmeJSONoptions (startLower $ nameBase n)) n

acmeJSONoptions :: String -> Options
acmeJSONoptions pre =
  defaultOptions
    {fieldLabelModifier = startLower . withoutPrefix, omitNothingFields = True}
  where
    withoutPrefix str =
      case stripPrefix pre str of
        Just x -> x
        Nothing ->
          error $
          "deriveAcmeJSON: ‘" ++ pre ++ "’ is not a prefix of ‘" ++ str ++ "’"

startLower :: String -> String
startLower [] = ""
startLower (x:xs) = toLower x : xs

secondsToMicroseconds :: Num a => a -> a
secondsToMicroseconds = (*) 1000000

-- | ACME only allows transport via HTTPS. Therefore the URL type is limited
-- To the @https:@ URI scheme.
data URL =
  URL URI
  deriving (Show)

isValidURL :: URI -> Bool
isValidURL = (== "https:") . uriScheme

instance FromJSON URL where
  parseJSON x = do
    u <- parseJSON x
    if isValidURL u
      then return (URL u)
      else fail "Unable to parse URI: scheme is not https"

instance ToJSON URL where
  toJSON (URL u) = toJSON u
