
# URI
[![JavaScript Style Guide](https://cdn.rawgit.com/standard/standard/master/badge.svg)](https://github.com/standard/standard)

URI class that can be used on relative URIs.

<br />

## Table of Contents
- [ Installation ](#install)
- [ Usage ](#usage)

<br />

<a name="install"></a>
## Install

```console
npm i @neumatter/uri
```

<br />

<a name="usage"></a>
## Usage

```js
import URI from '@neumatter/uri'

const uri = new URI('https://example.com/schemas/address#/properties/street_address')
// do something with uri
```

```js
import URI from '@neumatter/uri'

const uri = new URI('#/properties/street_address')
// do something with uri
```

```js
import URI from '@neumatter/uri'

const uri = new URI('/schemas/address')
// do something with uri
```

