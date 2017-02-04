module Network.ACME.Internal where

import Data.Aeson
import Data.Aeson.Types
import Data.Char
import Data.List
import GHC.Generics

parseAcmeServerResponse
  :: (Generic a, GFromJSON Zero (Rep a))
  => String -> Value -> Parser a
parseAcmeServerResponse pre = genericParseJSON (acmeJSONoptions pre)

acmeJSONoptions :: String -> Options
acmeJSONoptions pre =
  defaultOptions
  { fieldLabelModifier = f pre
  }
  where
    f pr str = foldr kebabKase "" (startLower withoutPrefix)
      where
        withoutPrefix =
          case stripPrefix pr str of
            Just x -> x
            Nothing -> error $ "JSON key " ++ str ++ " has no prefix " ++ pr
        startLower (x:xs) = toLower x : xs
        startLower [] = ""
        kebabKase x y
          | isAsciiLower x = x : y
          | otherwise = '-' : toLower x : y
          
toAcmeRequestBody :: (Generic a, GToJSON Zero (Rep a)) =>
  String -> a -> Value
toAcmeRequestBody pre = genericToJSON (acmeJSONoptions pre)

toAcmeConfigStore :: (Generic a, GToJSON Zero (Rep a)) =>
  String -> a -> Value
toAcmeConfigStore = toAcmeRequestBody
