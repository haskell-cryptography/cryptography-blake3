{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -fno-full-laziness #-}

-- | Module: Cryptography.BLAKE3
-- Description: BLAKE3 wrapper interface
-- Copyright: (C) Koz Ross 2022
-- License: BSD-3-Clause
-- Maintainer: koz.ross@retro-freedom.nz
-- Stability: Stable
-- Portability: GHC only
--
-- A higher-level interface to BLAKE3 hashing. Works in pure code, and allows
-- hashing of anything 'Storable'.
module Cryptography.BLAKE3
  ( -- * Types
    Blake3Hash,

    -- * Functions
    toByteArray,
    fromByteArray,
    hashBlake3,
  )
where

import Control.Monad.ST (ST, runST)
import Cryptography.BLAKE3.Bindings
  ( blake3HasherFinalize,
    blake3HasherInit,
    blake3HasherSize,
    blake3HasherUpdate,
    blake3OutLen,
  )
import Data.Foldable (traverse_)
import Data.Kind (Type)
import Data.Primitive.ByteArray
  ( ByteArray,
    copyByteArray,
    foldrByteArray,
    indexByteArray,
    mutableByteArrayContents,
    newAlignedPinnedByteArray,
    sizeofByteArray,
    unsafeFreezeByteArray,
    writeByteArray,
  )
import Data.Word (Word8)
import Foreign.Marshal.Alloc (alloca, free, mallocBytes)
import Foreign.Ptr (Ptr, castPtr)
import Foreign.Storable
  ( Storable
      ( alignment,
        peek,
        peekElemOff,
        poke,
        pokeElemOff,
        sizeOf
      ),
  )
import Numeric (showHex)
import System.IO.Unsafe (unsafeDupablePerformIO)

-- | @since 1.0
newtype Blake3Hash = B3H ByteArray
  deriving
    ( -- | @since 1.0
      Eq,
      -- | @since 1.0
      Ord
    )
    via ByteArray

-- | @since 1.0
instance Show Blake3Hash where
  {-# INLINEABLE show #-}
  show (B3H ba) = "Blake3Hash " <> foldrByteArray go "" ba
    where
      go :: Word8 -> String -> String
      go = showHex

-- | @since 1.0
instance Storable Blake3Hash where
  {-# INLINEABLE sizeOf #-}
  sizeOf _ = fromIntegral blake3OutLen
  {-# INLINEABLE alignment #-}
  alignment _ = fromIntegral blake3OutLen
  {-# INLINEABLE peek #-}
  peek p = do
    let hashLen = fromIntegral blake3OutLen
    mba <- newAlignedPinnedByteArray hashLen hashLen
    let p' :: Ptr Word8 = castPtr p
    traverse_ (\ix -> peekElemOff p' ix >>= writeByteArray mba ix) [0 .. hashLen - 1]
    ba <- unsafeFreezeByteArray mba
    pure . B3H $ ba
  {-# INLINEABLE poke #-}
  poke p (B3H ba) = do
    let p' :: Ptr Word8 = castPtr p
    traverse_ (\ix -> pokeElemOff p' ix . indexByteArray ba $ ix) [0 .. sizeofByteArray ba - 1]

-- | @since 1.0
toByteArray :: Blake3Hash -> ByteArray
toByteArray (B3H ba) = ba

-- | @since 1.0
fromByteArray :: ByteArray -> Maybe Blake3Hash
fromByteArray ba
  | sizeofByteArray ba == fromIntegral blake3OutLen = Just . B3H $ runST go
  | otherwise = Nothing
  where
    go :: forall (s :: Type). ST s ByteArray
    go = do
      let hashLen = fromIntegral blake3OutLen
      mba <- newAlignedPinnedByteArray hashLen hashLen
      copyByteArray mba 0 ba 0 hashLen
      unsafeFreezeByteArray mba

-- | @since 1.0
{-# NOINLINE hashBlake3 #-}
hashBlake3 ::
  forall (a :: Type).
  (Storable a) =>
  a ->
  Blake3Hash
hashBlake3 x = unsafeDupablePerformIO $ do
  let len = fromIntegral . sizeOf $ (undefined :: a)
  let hashLen = fromIntegral blake3OutLen
  mba <- newAlignedPinnedByteArray hashLen hashLen
  let hashPtr = mutableByteArrayContents mba
  hasherPtr <- mallocBytes . fromIntegral $ blake3HasherSize
  blake3HasherInit hasherPtr
  alloca $ \pData -> do
    poke pData x
    blake3HasherUpdate hasherPtr (castPtr pData) len
  blake3HasherFinalize hasherPtr hashPtr blake3OutLen
  free hasherPtr
  ba <- unsafeFreezeByteArray mba
  pure . B3H $ ba
