# Fractal Dao Contract

## Install

```
npm i
npm run compile 
```

## Config

> * 1 cp .env_example .env
> * 2 set WIF and UNISAT_API_KEY in .env

## Test

```
// stake
ts-node tests/testnet/buildStake.ts stake
// unstake
ts-node tests/testnet/buildStake.ts unstake a3e720751b450c7f71f81a8ccdf6eec36cd8e271e1e0d16329713ee13447c4b6 1
// unlock timelock
ts-node tests/testnet/buildStake.ts timeunlock 70a2dbae80e68fd542b1cebff0a653da96717e12fde21017c80cd4ac379e1f2e 1 4000
```
