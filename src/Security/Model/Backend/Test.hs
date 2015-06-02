{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ExistentialQuantification #-}
--------------------------------------------------------------------------
-- |
-- Module:      Security.Model.Backend.Test
-- Copyright:   (c) 2015 Martin Grabmueller
-- License:     BSD3
--
-- Maintainer:  martin@grabmueller.de
-- Stability:   provisional
-- Portability: portable
--
----------------------------------------------------------------------------
module Security.Model.Backend.Test(TestSecuritySystem(..),
                                   UserEntry(..)) where

import Security.Model.Types

import Data.Map(Map)
import qualified Data.Map as Map

data UserEntry = UserEntry {
  userEntryUserId :: UserId,
  userEntryUsernames :: [Username],
  userEntryPassword :: Maybe Password,
  userEntryTotpToken :: Maybe TotpToken,
  userEntryRoles :: [Role]
  }
                 
data TestSecuritySystem = TestSecuritySystem {
  usersFromName :: Map Username UserEntry,
  usersFromId :: Map UserId UserEntry,
  rolesParents :: Map Role [Role],
  rolesPermissions :: Map Role [Permission]
  }

instance SecurityBackend TestSecuritySystem where
  supportedMechanisms (TestSecuritySystem{}) =
    [AuthenticationUserPassword, AuthenticationTotp]

  userNameToUserId (TestSecuritySystem{..}) name =
    case Map.lookup name usersFromName of
      Nothing -> return $ Left UnknownUser
      Just UserEntry{..} -> return $ Right userEntryUserId

  verifyUserPassword (TestSecuritySystem{..}) _ (IsUser uid) name pw =
    case Map.lookup name usersFromName of
      Nothing -> return $ Left UnknownUser
      Just UserEntry{..} ->
        case userEntryPassword of
          Nothing -> return $ Left UnsupportedAuthenticationMechanism
          Just userPw ->
            if userEntryUserId == uid && any (== name) userEntryUsernames && userPw == pw
            then return $ Right ()
            else return $ Left PasswordMismatch
  verifyTotp (TestSecuritySystem{..}) SecurityContext{..} (IsUser cuid) ts token =
    case Map.lookup cuid usersFromId of
      Nothing -> return $ Left UnknownUser
      Just UserEntry{..} ->
        case userEntryTotpToken of
          Nothing -> return $ Left UnsupportedAuthenticationMechanism
          Just userTok ->
            case authenticatedEntity of
              EntityUser userId ->
                if cuid == userId && userEntryUserId == userId && userTok == token
                then return $ Right ()
                else return $ Left TotpTokenMismatch
              _  ->
                return $ Left UnknownEntity

  userRoles TestSecuritySystem{..} SecurityContext{..} userId =
    case Map.lookup userId usersFromId of
      Nothing -> return $ Left UnknownUser
      Just UserEntry{..} ->
        return $ Right  userEntryRoles

  rolePermissions TestSecuritySystem{..} SecurityContext{..} role =
    case Map.lookup role rolesPermissions of
      Nothing -> return $ Right []
      Just p -> return $ Right p

  roleParents TestSecuritySystem{..} SecurityContext{..} role =
    case Map.lookup role rolesParents of
      Nothing -> return $ Right []
      Just p -> return $ Right p
