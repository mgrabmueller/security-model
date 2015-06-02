{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ExistentialQuantification #-}
--------------------------------------------------------------------------
-- |
-- Module:      Security.Model.Types
-- Copyright:   (c) 2015 Martin Grabmueller
-- License:     BSD3
--
-- Maintainer:  martin@grabmueller.de
-- Stability:   provisional
-- Portability: portable
--
----------------------------------------------------------------------------
module Security.Model.Types
       (-- * Security Backend
        SecurityBackend(..),
        SecuritySystem(..),
        -- * Basic types
        Username(..),
        Password(..),
        ServiceName(..),
        TotpToken(..),
        UserId(..),
        ServiceId(..),
        Timestamp(..),
        Claim(..),
        Credential(..),
        Entity(..),
        AuthenticationMechanism(..),
        Identity(..),
        -- * Security context
        SecurityContext(..),
        securityContextEntity,
        securityContextMechanisms,
        -- * Errors
        SecurityError(..),
        -- * Utility functions
        claimToEntity,
        entityToClaim,
        credentialToMechanism,
        -- * Value validation
        validateUsername,
        validatePassword,
        validateTimestamp,
        validateToken,
        -- * Permissions
        PermissionName(..),
        Permission(..),
        permissionImplied,
        -- * Roles
        Rolename(..),
        Role(..)
       ) where

import Data.Text(Text)
import qualified Data.Text as T
import Data.Time.Clock(UTCTime, getCurrentTime)
import Data.Map(Map)
import qualified Data.Set as Set
import Data.Set(Set)
import Control.Applicative
import Control.Monad

class SecurityBackend a where
  supportedMechanisms :: a -> [AuthenticationMechanism]
  userNameToUserId :: a -> Username -> IO (Either SecurityError UserId)
  verifyUserPassword :: a -> SecurityContext -> Claim -> Username -> Password -> IO (Either SecurityError ())
  verifyTotp :: a -> SecurityContext -> Claim -> Timestamp -> TotpToken -> IO (Either SecurityError ())
  userRoles :: a -> SecurityContext -> UserId -> IO (Either SecurityError [Role])
  rolePermissions :: a -> SecurityContext -> Role -> IO (Either SecurityError [Permission])
  roleParents :: a -> SecurityContext -> Role -> IO (Either SecurityError [Role])

data SecuritySystem = forall b. SecurityBackend b => SecuritySystem b

-- | Username is a human-readable name used for authentication
-- purposes in the username/password scheme. This is not necessarily
-- the same as a 'UserId', but can be.
--
newtype Username = Username Text
  deriving (Eq, Ord, Show)

-- | Password are human-readable relatively short strings (about 8 to
-- 20 characters) used for authentication purposes in the
-- username/password scheme.
--
newtype Password = Password Text
  deriving (Eq, Ord, Show)

-- | A service name is a relatively short identifier for naming
-- services that need to authenticate.
--
newtype ServiceName = ServiceName Text
  deriving (Eq, Show)

-- | A 'TotpToken' is a sequence of digits produced by a TOTP device
-- or application, normally 6 digits long.  This is used as an
-- additional authentication factor in the TOTP authentication scheme.
--
newtype TotpToken = TotpToken Text
  deriving (Eq, Show)

-- | Internal identifier for users.
--
newtype UserId = UserId Text
  deriving (Eq, Ord, Show)

-- | Internal identifier for services.
--
newtype ServiceId = ServiceId Text
  deriving (Eq, Show)

-- | Timestamp.
--
newtype Timestamp = Timestamp UTCTime
  deriving (Eq)

instance Show Timestamp where
  show (Timestamp t) = "<<timestamp>>"

data Claim
  = IsUser UserId
  | IsService ServiceId
  deriving (Eq, Show)

data Credential
  = CredPassword Username Password
  | CredTotpToken Timestamp TotpToken
  deriving (Eq, Show)

data Entity
  = EntityUnknown
  | EntityUser UserId
  | EntityService ServiceId
  deriving (Eq, Show)

data AuthenticationMechanism
  = AuthenticationUserPassword
  | AuthenticationTotp
  deriving (Eq, Show)

data Identity = Identity Entity
  deriving (Eq, Show)

data SecurityContext
  = SecurityContext {
    authenticatedIdentity :: Identity,
    authenticatedEntity :: Entity,
    authenticatedThrough :: AuthenticationMechanism,
    authenticatedThroughAll :: [AuthenticationMechanism],
    authenticationTimestamp :: Timestamp,
    authenticationInheritedContext :: SecurityContext,
    roles :: [Role]
    }
  | SecurityContextNone
  deriving (Eq, Show)

securityContextEntity :: SecurityContext -> Entity
securityContextEntity SecurityContextNone = EntityUnknown
securityContextEntity SecurityContext{..} = authenticatedEntity

securityContextMechanisms :: SecurityContext -> [AuthenticationMechanism]
securityContextMechanisms SecurityContextNone = []
securityContextMechanisms SecurityContext{..} = authenticatedThroughAll

data SecurityError
  = UnknownUser
  | UnknownService
  | UnknownEntity
  | PasswordMismatch
  | TotpTokenMismatch
  | SecurityContextMissing
  | UnsupportedAuthenticationMechanism
  | InvalidValue Text
  | Unauthorized
  deriving (Eq, Show)

claimToEntity :: Claim -> Entity
claimToEntity (IsUser userId) = EntityUser userId
claimToEntity (IsService serviceId) = EntityService serviceId

entityToClaim :: Entity -> Claim
entityToClaim (EntityUser userId) = IsUser userId
entityToClaim (EntityService serviceId) = IsService serviceId

credentialToMechanism :: Credential -> AuthenticationMechanism
credentialToMechanism CredPassword{} = AuthenticationUserPassword
credentialToMechanism CredTotpToken{} = AuthenticationTotp

validateTimestamp ts act = act
validateUsername (Username username) act
  | T.null username || T.length username > 1024 = validateError (InvalidValue "username")
  | otherwise = act

validatePassword (Password password) act 
  | T.null password || T.length password > 1024 = validateError (InvalidValue "password")
  | otherwise = act
validateToken (TotpToken token) act
  | T.length token /= 6 = validateError (InvalidValue "TOTP token")
  | otherwise = act

validateError :: SecurityError -> IO (Either SecurityError a)
validateError err = return $ Left err

newtype PermissionName = PermissionName Text
  deriving (Eq, Show)

data Permission = Permission PermissionName
  deriving (Eq, Show)

permissionImplied :: Permission -> Permission -> Bool
permissionImplied p1 p2 = False

data Rolename = Rolename Text
  deriving (Eq, Ord, Show)
           
data Role = Role {
  roleName :: Rolename
  }
  deriving (Eq, Ord, Show)

data Rolemap = Rolemap {
  rolemapIdentityRoles :: Map Identity [Rolename],
  rolemapRoles :: Map Rolename Role
  }
