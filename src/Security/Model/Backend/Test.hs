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
module Security.Model.Backend.Test(TestSecuritySystem(..)) where

import Security.Model.Types

data TestSecuritySystem = TestSecuritySystem [(Username, UserId)] (Maybe (Username, Password)) (Maybe (UserId, TotpToken))

instance SecurityBackend TestSecuritySystem where
  supportedMechanisms (TestSecuritySystem _ mbUP mbT) =
    (case mbUP of Just _ -> [AuthenticationUserPassword]; _ -> []) ++
    (case mbT of Just _ -> [AuthenticationTotp]; _ -> [])

  userNameToUserId (TestSecuritySystem map _ _ ) name =
    case lookup name map of
      Nothing -> return $ Left UnknownUser
      Just uid -> return $ Right uid

  verifyUserPassword (TestSecuritySystem _ Nothing _) _ _ _ _ =
    return $ Left UnsupportedAuthenticationMechanism
  verifyUserPassword (TestSecuritySystem map (Just (u, p)) _) _ (IsUser uid) name pw =
    case lookup name map of
      Nothing -> return $ Left UnknownUser
      Just nameuid ->
        if nameuid == uid &&  u == name && p == pw
        then return $ Right ()
        else return $ Left PasswordMismatch
  verifyTotp (TestSecuritySystem _ _ Nothing) _ _ _ _ =
    return $ Left UnsupportedAuthenticationMechanism
  verifyTotp (TestSecuritySystem _ _ (Just (uid, t))) SecurityContext{..} (IsUser cuid) ts token =
    case authenticatedEntity of
      EntityUser userId ->
        if cuid == userId && uid == userId && t == token
        then return $ Right ()
        else return $ Left TotpTokenMismatch
      _  ->
        return $ Left UnknownEntity
