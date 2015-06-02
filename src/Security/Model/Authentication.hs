{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ExistentialQuantification #-}
--------------------------------------------------------------------------
-- |
-- Module:      Security.Model.Authentication
-- Copyright:   (c) 2015 Martin Grabmueller
-- License:     BSD3
--
-- Maintainer:  martin@grabmueller.de
-- Stability:   provisional
-- Portability: portable
--
----------------------------------------------------------------------------
module Security.Model.Authentication
       (passwordAuthenticate,
        totpAuthenticate) where

import Security.Model.Types

-- | 'verifyClaim' makes sure that the given claim is valid by testing
-- the given credential in connection with the given
-- 'SecurityContext'.  Some credentials only make sense with a proper
-- security context, e.g. a TOTP token can only be verified when the
-- entity has already been verified by another means.
--
verifyClaim :: SecuritySystem -> SecurityContext -> Claim -> Credential -> IO (Either SecurityError ())
verifyClaim (SecuritySystem secSystem) secCtxt claim (CredPassword username password) =
  verifyUserPassword secSystem secCtxt claim username password
verifyClaim (SecuritySystem secSystem) secCtxt claim (CredTotpToken ts token) =
  verifyTotp secSystem secCtxt claim ts token


-- | Authenticate a claim against the given credentials and return a
-- security context on success. Return an error if authentication
-- fails.
--
authenticate :: SecuritySystem -> SecurityContext -> Timestamp -> Claim -> Credential -> IO (Either SecurityError SecurityContext)
authenticate secSystem inhSecCtxt now claim credential = do
  eRes <- verifyClaim secSystem inhSecCtxt claim credential
  case eRes of
    Left err -> return $ Left err
    Right _ -> do
      let entity = claimToEntity claim
          secCtxt = SecurityContext {
            authenticatedIdentity = Identity entity,
            authenticatedEntity = entity,
            authenticatedThrough = credentialToMechanism credential,
            authenticatedThroughAll = [credentialToMechanism credential] ++ securityContextMechanisms inhSecCtxt,
            authenticationTimestamp = now,
            authenticationInheritedContext = inhSecCtxt,
            roles = []
            }
      return $ Right secCtxt


-- Perform username\/password authentication.
--
passwordAuthenticate :: SecuritySystem ->
                        Timestamp ->
                        Username ->
                        Password ->
                        IO (Either SecurityError SecurityContext)
passwordAuthenticate secSystem@(SecuritySystem sys) now username pw =
  validateTimestamp now $ validateUsername username $ validatePassword pw $ do
  eUserId <- userNameToUserId sys username
  case eUserId of
    Left err -> return $ Left err
    Right userId -> do
      let claim = IsUser userId
          credential = CredPassword username pw
      authenticate secSystem SecurityContextNone now claim credential


-- | Perform TOTP authentication.
--
totpAuthenticate :: SecuritySystem ->
                    SecurityContext ->
                    Timestamp ->
                    TotpToken ->
                    IO (Either SecurityError SecurityContext)
totpAuthenticate _ SecurityContextNone _ _=
  return $ Left SecurityContextMissing
totpAuthenticate secSystem inhSecCtxt@SecurityContext{..} now token =
  validateTimestamp now $ validateToken token $ do
  let claim = entityToClaim authenticatedEntity
      credential = CredTotpToken now token
  authenticate secSystem inhSecCtxt now claim credential
