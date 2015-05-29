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
       () where

import Security.Model.Types

authorize :: SecuritySystem ->
             SecurityContext ->
             Permission ->
             IO (Either SecurityError SecurityContext)
authorize secSys secCtxt perm =
  return $ Left Unauthorized
