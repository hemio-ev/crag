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
acmeJSONoptions pre = defaultOptions {fieldLabelModifier = f pre}
  where
    f pr str = kebabKase False (startLower withoutPrefix) []
      where
        withoutPrefix =
          case stripPrefix pr str of
            Just x -> x
            Nothing -> ""
        startLower (x:xs) = toLower x : xs
        startLower [] = ""
        kebabKase :: Bool -> String -> String -> String
        kebabKase _ [] ys = ys
        kebabKase _ ('_':xs) ys = kebabKase True xs ys
        kebabKase True (x:xs) ys = kebabKase False xs (ys ++ [toUpper x])
        kebabKase False (x:xs) ys
          | isAsciiLower x = kebabKase False xs (ys ++ [x])
          | otherwise = kebabKase False xs (ys ++ ['-', toLower x])

toAcmeRequestBody
  :: (Generic a, GToJSON Zero (Rep a))
  => String -> a -> Value
toAcmeRequestBody pre = genericToJSON (acmeJSONoptions pre)

toAcmeConfigStore
  :: (Generic a, GToJSON Zero (Rep a))
  => String -> a -> Value
toAcmeConfigStore = toAcmeRequestBody
