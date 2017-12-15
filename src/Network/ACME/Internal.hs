module Network.ACME.Internal where

import Data.Aeson
import Data.Aeson.TH (deriveJSON)
import Data.Aeson.Types
import Data.Char
import Data.List
import GHC.Generics
import Language.Haskell.TH.Syntax (Dec, Name, Q, nameBase)

parseAcmeServerResponse ::
     (Generic a, GFromJSON Zero (Rep a)) => String -> Value -> Parser a
parseAcmeServerResponse pre = genericParseJSON (acmeJSONoptions pre)

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

toAcmeRequestBody :: (Generic a, GToJSON Zero (Rep a)) => String -> a -> Value
toAcmeRequestBody pre = genericToJSON (acmeJSONoptions pre)

toAcmeConfigStore :: (Generic a, GToJSON Zero (Rep a)) => String -> a -> Value
toAcmeConfigStore = toAcmeRequestBody
