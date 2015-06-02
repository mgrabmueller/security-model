{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ExistentialQuantification #-}
--------------------------------------------------------------------------
-- |
-- Module:      Security.Model.Authorization
-- Copyright:   (c) 2015 Martin Grabmueller
-- License:     BSD3
--
-- Maintainer:  martin@grabmueller.de
-- Stability:   provisional
-- Portability: portable
--
----------------------------------------------------------------------------
module Security.Model.Authorization
       (authorize) where

import Security.Model.Types
import Data.Set(Set)
import qualified Data.Set as Set
import Control.Monad
import Control.Applicative

-- | Ensure that the given security context has at least the given
-- permissions. If not, return an error. Otherwise, invoke the given
-- action and return it's result.
--
authorize :: SecuritySystem ->
             SecurityContext ->
             [Permission] ->
             (SecurityContext -> Security a) ->
             IO (Either SecurityError a)
authorize secSys secCtxt reqPerms action =
  runSecurity (authorize' secCtxt reqPerms action) secSys

authorize' :: SecurityContext ->
             [Permission] ->
             (SecurityContext -> Security a) ->
             Security a
authorize' secCtxt@SecurityContext{..} reqPerms action =
  case authenticatedIdentity of
    Identity (EntityUser userId) -> do
      perms <- userPermissions secCtxt userId
      let allowed = all (\ p -> p `elem` perms) reqPerms
      if allowed
        then action secCtxt
        else raiseSecurityError Unauthorized
    _ -> raiseSecurityError Unauthorized
  
-- | Calculate the transitive closure of roles, as given by the role
-- inheritance relation of the security system.
--
closeRoles :: SecurityContext -> [Role] -> Security [Role]
closeRoles secCtxt roles = do
  Set.toList <$> go (Set.fromList roles)
 where
   go :: Set Role -> Security (Set Role)
   go roles = do
     SecuritySystem sys <- getSecuritySystem
     parents <- mapM (\ role -> liftIOtoSecurity $ roleParents sys secCtxt role)
                (Set.toList roles)
     let roles' = roles `Set.union` Set.fromList (concat parents)
     if roles' /= roles
       then go roles'
       else return roles

-- | Calculate the list of permissions of the given user.
--
userPermissions :: SecurityContext -> UserId -> Security [Permission]
userPermissions secCtxt userId = do
  SecuritySystem sys <- getSecuritySystem
  uRoles <- liftIOtoSecurity $ userRoles sys secCtxt userId
  roles <- closeRoles secCtxt uRoles
  ePerms <- mapM (\  role ->  liftIOtoSecurity $ rolePermissions sys secCtxt role)
            roles
  return $ concat ePerms
      
