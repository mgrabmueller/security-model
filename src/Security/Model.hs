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
import Security.Model.Authorization
import Security.Model.Backend.Test

import Data.Map(Map)
import qualified Data.Map as Map
import Data.Time.Clock(UTCTime, getCurrentTime)
import Control.Applicative
import qualified Data.Text as T

test = do
  let username = Username "hilbert@princeton.edu"
      password = Password "secert"
      nullPassword = Password ""
      longPassword = Password (T.replicate 1025 "X")
      token = TotpToken "123456"
  now <- Timestamp <$> getCurrentTime
  Left UnknownUser <- run noUsersSecuritySystem now username password token
  Left UnsupportedAuthenticationMechanism <- run noPwSecuritySystem now username password token
  Left PasswordMismatch <- run wrongPwSecuritySystem now username password token
  Left UnsupportedAuthenticationMechanism <- run pwOnlySecuritySystem now username password token
  Left (InvalidValue _) <- run pwOnlySecuritySystem now username nullPassword token 
  Left (InvalidValue _) <- run pwOnlySecuritySystem now username longPassword token 
  Right () <- run pwTotpSecuritySystem now username password token
  Left TotpTokenMismatch <- run pwWrongTotpSecuritySystem now username password token

  let secSys = pwTotpSecuritySystem
  Right sc <- passwordAuthenticate secSys now username password
  res@(Left Unauthorized) <- authorize secSys sc [Permission (PermissionName "killimp")]
                             (\ _ _ -> return $ Right True)
  res@(Right True) <- authorize secSys sc [Permission (PermissionName "flipswitch")]
                      (\ _ _ -> return $ Right True)
  res@(Left Unauthorized) <- authorize secSys sc [Permission (PermissionName "killimp"),
                                                  Permission (PermissionName "flipswitch")]
                             (\ _ _ -> return $ Right True)
  res@(Right True) <- authorize secSys sc [Permission (PermissionName "compile"),
                                           Permission (PermissionName "flipswitch")]
                      (\ _ _ -> return $ Right True)
  return ()


run :: SecuritySystem -> Timestamp -> Username -> Password -> TotpToken ->
       IO (Either SecurityError ())
run secSystem now username pw token = do
  eSc <- passwordAuthenticate secSystem now  username pw
  case eSc of
    Left err -> do
      return $ Left err
    Right sc -> do
      eSc' <- totpAuthenticate secSystem sc now token
      case eSc' of
        Left err -> do
          return $ Left err
        Right sc' -> do
          return $ Right ()
  
noUsersSecuritySystem :: SecuritySystem
noUsersSecuritySystem =
  SecuritySystem $ TestSecuritySystem Map.empty Map.empty Map.empty Map.empty

hilbert :: UserEntry
hilbert = UserEntry {
  userEntryUserId = UserId "hilbert",
  userEntryUsernames = [Username "hilbert@princeton.edu"],
  userEntryPassword = Just $ Password "secert",
  userEntryTotpToken = Just $ TotpToken "123456",
  userEntryRoles = [Role (Rolename "admin")]
}

hilbertNoPw = hilbert{userEntryPassword = Nothing}
hilbertNoTotp = hilbert{userEntryTotpToken = Nothing}
hilbertNoPwNoTotp = hilbertNoPw{userEntryTotpToken = Nothing}
hilbertWrongPwNoTotp = hilbertNoTotp{userEntryPassword = Just $ Password "geheim"}
hilbertWrongTotp = hilbert{userEntryTotpToken = Just $ TotpToken "654321"}
                                                
noPwSecuritySystem :: SecuritySystem
noPwSecuritySystem =
  SecuritySystem $ TestSecuritySystem (Map.singleton (Username "hilbert@princeton.edu") hilbertNoPwNoTotp)
  (Map.singleton (UserId "hilbert") hilbertNoPwNoTotp)
  rParents
  rPermissions

wrongPwSecuritySystem :: SecuritySystem
wrongPwSecuritySystem =
  SecuritySystem $
  TestSecuritySystem (Map.singleton (Username "hilbert@princeton.edu") hilbertWrongPwNoTotp)
  (Map.singleton (UserId "hilbert") hilbertWrongPwNoTotp)
  rParents
  rPermissions

pwOnlySecuritySystem :: SecuritySystem
pwOnlySecuritySystem =
  SecuritySystem $
  TestSecuritySystem (Map.singleton (Username "hilbert@princeton.edu") hilbertNoTotp)
  (Map.singleton (UserId "hilbert") hilbertNoTotp)
  rParents
  rPermissions

pwTotpSecuritySystem :: SecuritySystem
pwTotpSecuritySystem =
  SecuritySystem $
  TestSecuritySystem (Map.singleton (Username "hilbert@princeton.edu") hilbert)
  (Map.singleton (UserId "hilbert") hilbert)
  rParents
  rPermissions
  
pwWrongTotpSecuritySystem :: SecuritySystem
pwWrongTotpSecuritySystem =
  SecuritySystem $
  TestSecuritySystem (Map.singleton (Username "hilbert@princeton.edu") hilbertWrongTotp)
  (Map.singleton (UserId "hilbert") hilbertWrongTotp)
  rParents
  rPermissions

rParents :: Map Role [Role]
rParents = Map.singleton (Role (Rolename "admin")) [(Role (Rolename "omni"))]

rPermissions :: Map Role [Permission]
rPermissions = Map.fromList
  [ (Role (Rolename "omni"), [Permission (PermissionName "flipswitch")]),
    (Role (Rolename "admin"), [Permission (PermissionName "compile")])
  ]
