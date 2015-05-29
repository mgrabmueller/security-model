{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ExistentialQuantification #-}
--------------------------------------------------------------------------
-- |
-- Module:      Security.Model
-- Copyright:   (c) 2015 Martin Grabmueller
-- License:     BSD3
--
-- Maintainer:  martin@grabmueller.de
-- Stability:   provisional
-- Portability: portable
--
----------------------------------------------------------------------------
module Security.Model() where

import Security.Model.Types
import Security.Model.Authentication
import Security.Model.Backend.Test

import Data.Time.Clock(UTCTime, getCurrentTime)
import Control.Applicative
import qualified Data.Text as T

test = do
  let username = Username "hilbert@princeton.edu"
      password = Password "letmein"
      nullPassword = Password ""
      longPassword = Password (T.replicate 1025 "X")
      token = TotpToken "123456"
  now <- Timestamp <$> getCurrentTime
  putStrLn "\n*** no users"
  run noUsersSecuritySystem now username password token
  putStrLn "\n*** no passwords"
  run noPwSecuritySystem now username password token
  putStrLn "\n*** wrong password"
  run wrongPwSecuritySystem now username password token
  putStrLn "\n*** passwords only"
  run pwOnlySecuritySystem now username password token 
  putStrLn "\n*** passwords only with empty password"
  run pwOnlySecuritySystem now username nullPassword token 
  putStrLn "\n*** passwords only with too long password"
  run pwOnlySecuritySystem now username longPassword token 
  putStrLn "\n*** passwords and totp"
  run pwTotpSecuritySystem now username password token
  putStrLn "\n*** passwords and wrong totp"
  run pwWrongTotpSecuritySystem now username password token

  return ()


run :: SecuritySystem -> Timestamp -> Username -> Password -> TotpToken -> IO Bool
run secSystem now username pw token = do
  putStr "password: "
  eSc <- passwordAuthenticate secSystem now  username pw
  case eSc of
    Left err -> do
      print err
      return False
    Right sc -> do
      putStrLn $ "ok: " ++ show sc
      putStr "totp: "
      eSc' <- totpAuthenticate secSystem sc now token
      case eSc' of
        Left err -> do
          print err
          return False
        Right sc' -> do
          putStrLn $ "ok: " ++ show sc'
          return True
  
noUsersSecuritySystem :: SecuritySystem
noUsersSecuritySystem =
  SecuritySystem $ TestSecuritySystem [] Nothing Nothing

noPwSecuritySystem :: SecuritySystem
noPwSecuritySystem =
  SecuritySystem $ TestSecuritySystem [(Username "hilbert@princeton.edu", UserId "hilbert")] Nothing Nothing

wrongPwSecuritySystem :: SecuritySystem
wrongPwSecuritySystem =
  SecuritySystem $
  TestSecuritySystem [(Username "hilbert@princeton.edu", UserId "hilbert")]
  (Just (Username "hilbert@princeton.edu", Password "secert"))
  Nothing

pwOnlySecuritySystem :: SecuritySystem
pwOnlySecuritySystem =
  SecuritySystem $
  TestSecuritySystem [(Username "hilbert@princeton.edu", UserId "hilbert")]
  (Just (Username "hilbert@princeton.edu", Password "letmein"))
  Nothing

pwTotpSecuritySystem :: SecuritySystem
pwTotpSecuritySystem =
  SecuritySystem $
  TestSecuritySystem [(Username "hilbert@princeton.edu", UserId "hilbert")]
  (Just (Username "hilbert@princeton.edu", Password "letmein"))
  (Just (UserId "hilbert", TotpToken "123456"))
  
pwWrongTotpSecuritySystem :: SecuritySystem
pwWrongTotpSecuritySystem =
  SecuritySystem $
  TestSecuritySystem [(Username "hilbert@princeton.edu", UserId "hilbert")]
  (Just (Username "hilbert@princeton.edu", Password "letmein"))
  (Just (UserId "hilbert", TotpToken "654321"))
