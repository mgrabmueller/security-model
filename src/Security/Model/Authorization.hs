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

authorize :: SecuritySystem ->
             SecurityContext ->
             [Permission] ->
             (SecuritySystem -> SecurityContext -> IO (Either SecurityError a)) ->
             IO (Either SecurityError a)
authorize secSys secCtxt@SecurityContext{..} reqPerms action =
  case authenticatedIdentity of
    Identity (EntityUser userId) -> do
      ePerms <- userPermissions secSys secCtxt userId
      case ePerms of
        Left err -> return $ Left err
        Right perms -> do
          let allowed = all (\ p -> p `elem` perms) reqPerms
          if allowed
            then action secSys secCtxt
            else return $ Left Unauthorized
    _ -> return $ Left Unauthorized
  

closeRoles :: SecuritySystem -> SecurityContext -> [Role] -> IO (Either SecurityError [Role])
closeRoles secSystem@(SecuritySystem sys) secCtxt roles = do
  eRoles <- go (Set.fromList roles)
  case eRoles of
    Left err -> return $ Left err
    Right roles ->
      return $ Right (Set.toList roles)
 where
   go :: Set Role -> IO (Either SecurityError (Set Role))
   go roles = do
     eParents <- foldM (\ acc role -> do
                           case acc of
                             Left err -> return $ Left err
                             Right parents -> do
                               e <- roleParents sys secCtxt role
                               case e of
                                 Left err -> return $ Left err
                                 Right eP ->
                                   return $ Right (eP ++ parents)) (Right []) (Set.toList roles)
     case eParents of
       Left err -> return $ Left err
       Right parents -> do
         let roles' = roles `Set.union` Set.fromList parents
         if roles' /= roles
           then go roles'
           else return $ Right roles
   
userPermissions :: SecuritySystem -> SecurityContext -> UserId -> IO (Either SecurityError [Permission])
userPermissions secSystem@(SecuritySystem sys) secCtxt userId = do
  euRoles <- userRoles sys secCtxt userId
  case euRoles of
    Left err -> return $ Left err
    Right uRoles -> do
      eRoles <- closeRoles secSystem secCtxt uRoles
      case eRoles of
        Left err -> return $ Left err
        Right roles -> do
          ePerms <- foldM (\ acc role -> do
                              case acc of
                                Left err -> return $ Left err
                                Right oldPerms -> do
                                  ep <- rolePermissions sys secCtxt role
                                  case ep of
                                    Left err -> return $ Left err
                                    Right p -> return $ Right $  p ++ oldPerms)
                    (Right [])
                    roles
          return ePerms
      
