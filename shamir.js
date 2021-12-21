/*
 * Based on "Shamir's Secret Sharing class" from Kenny Millington
 *
 * @link   https://www.kennynet.co.uk/misc/shamir.class.txt
 */

var Forfex = function() {
	const Q = 257

	var _invtab = null

	var invtab = function() {
		if( /*self::*/_invtab == null ) {
			let x = 1, y = 1
			/*self::*/_invtab = []
			for(let i = 0; i < /*self::*/Q; ++i) {
				/*self::*/_invtab[x] = y
				x = /*self::*/modq(3 * x)
				y = /*self::*/modq(86 * y)
			}
		}

		return /*self::*/_invtab
	}

	var modq = function(number) {
		let mod = number % /*self::*/Q
		return (mod < 0) ? mod + /*self::*/Q : mod
	}

	var inv = function(i) {
		let $invtab = /*self::*/invtab()
		return (i < 0) ? /*self::*/modq(-$invtab[-i]) : $invtab[i]
	}

	var rcoeffs = function(key_x, quorum) {
		let coeffs = []

		for(let i = 0; i < quorum; ++i) {
			let temp = 1
			for(let j = 0; j < quorum; ++j) {
				if(i != j) {
					temp = /*self::*/modq( -temp * key_x[j] *
							/*self::*/inv( key_x[i] - key_x[j] ) )
				}
			}

			if(temp == 0) {
				/* Repeated share. */
				throw "Forfex.rcoeffs(): Repeated share detected - cannot compute reverse-coefficients!"
			}

			coeffs.push( temp )
		}

		return coeffs
	}

	var thresh = function(byte, number, quorum) {
		coeffis = /*self::*/coeffs(quorum)
		coeffis.push( byte )

		let result = []
		for(let i = 0; i < number; ++i)
			result.push( /*self::*/horner(i + 1, coeffis) )

		return result
	}

	var coeffs = function(quorum) {
		$coeffs = []
		for(let i = 0; i < quorum - 1; ++i) {
			$coeffs.push( /*self::*/modq( Math.floor(Math.random() * 65535) ) )
		}
		return $coeffs
	}

	var horner = function(x, coeffs) {
		let val = 0
		for(const c of coeffs)
			val = /*self::*/modq(x * val + c)
		return val
	}

	//https://stackoverflow.com/a/68545179
	this.dataToUint8Array = async function(data) {
		if(data instanceof Blob) {
			const arrayBuffer = await data.arrayBuffer()
			return new Uint8Array(arrayBuffer)
		}
		//~ console.log("data es Text")
		const encoder = new TextEncoder()
		return encoder.encode(data)
	}

	this.hash = async (msgUint8) => { // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest#converting_a_digest_to_a_hex_string
		const hashBuffer = await crypto.subtle.digest("SHA-256", msgUint8)
		const hashArray = Array.from(new Uint8Array(hashBuffer))
		return hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
	}

	var downloadURL = (data, fileName, lugar) => {
		const enlaces = document.getElementById( lugar )
		const a = document.createElement("a")
		a.href = data
		a.appendChild( document.createTextNode(fileName) )
		a.download = fileName
		enlaces.appendChild(a)
		enlaces.appendChild( document.createElement("br") )
	}

	this.downloadBlob = (data, fileName, mimeType, lugar, duration = 0) => {
		const blob = new Blob([data], {
			type: mimeType
		})

		const url = window.URL.createObjectURL(blob)

		downloadURL(url, fileName, lugar)

		if(duration > 0) {
			setTimeout(() => window.URL.revokeObjectURL(url), duration)
		}
	}

	/**
	 * @param secret is binary buffer.
	 */
	this.share = function(secret, number, quorum = null) {
		if(number > /*self::*/Q - 1 || number < 0) {
			throw new Error(
				"Forfex.share(): number ($number) needs to be between 0 and " +
				(/*self::*/Q - 1) + "."
			)
		}

		if(quorum == null) {
			quorum = Math.floor(number / 2 ) + 1
		}
		else {
			if(quorum > number) {
				throw new Error(
					"Forfex.share(): Quorum ($quorum) cannot exceed number " +
					`(${number}).`
				)
			}
		}

		let result = []

		for(byte of secret/*message*/) {
			for(const $sub_result of /*self::*/thresh(byte, number, quorum) ) {
				result.push( $sub_result )
			}
		}
		const len = secret.length

		let keys = []

		//~ //Saving in hexadecimal
		for(let i = 0; i < number; ++i) {
			const len2 = len + 2
			let key = new Uint8Array(len2)
			key[0] = quorum
			key[1] = i + 1

			for(let j = 2, $j = 0; j < key.length; ++j) {
				let t = result[$j * number + i]
				key[j] = t > 255 ? t - 255 : t
				++$j
			}
			keys.push(key)
		}

		return keys;
	}

	this.recover = function(keys) {
		let key_x = []
		let key_y = []

		let keylen, quorum, number

		for(let key of keys) {
			quorum = key[0]
			number = key[1]
			keylen = key.length
			key_x.push( number )

			for(let i = 2; i < keylen; ++i) {
				//Warning with 256
				//~ key_y.push( key[i] != 0 ? key[i] : 256 )
				key_y.push( key[i] )
			}
		}

		keylen -= 2

		let coeffs = /*self::*/rcoeffs(key_x, quorum)

		let secret = new Uint8Array(keylen)
		for(let i = 0; i < keylen; ++i) {
			let temp = 0
			for(let j = 0; j < quorum; ++j) {
				temp = /*self::*/modq(temp + key_y[keylen * j + i] *
								coeffs[j])
			}
			secret[i] = temp
		}

		return secret;
	}
}
