/*
 * Based on "Shamir's Secret Sharing class" from Kenny Millington
 *
 * @link   https://www.kennynet.co.uk/misc/shamir.class.txt
 *
 * Se trabaja en el campo Z_p* = {1, 2, ..., p-1}.
 * Los polinomios están en Z_p*[x].
 * En Z_p* el neutro multiplicativo es el 1, entonces si el inverso de n es m, se cumple n*m  = 1 (mod p).
 * Para hallar el inverso de un elemento de Z_p*, se usa el algoritmo de euclides extendido o como en este caso, 
 * generar una criba de inversos a partir de un par de inversos.
 *
 */

var Forfex = function() {
	//const Q = 257 // primo obsoleto
	
	// El primo 65537 satisface: 
	// 1. Es el menor primo más grande que 2 bytes, FFFF = 65535 base 10.
	// 2. El campo que resulta es Z_p*={1, 2, ..., 65536}, por lo cual el único valor conflictivo es el 65536
	// que directamente como byte de entrada no puede existir, pero sí al hallar el inverso de cualquier otro número,
	// sin embargo 65536 es un número cuyo inverso es el mismo, entonces cualquier conflicto se desvanece. 
	// 3. Los dos primos semillas elegidos 3 y 21846 se comportan adecuadamente en la tabla de inversos
	const Q = 65537 // p = 65537 


	// Tabla cacheada de valores inversos de Z_p*
	var _invtab = null

	// Construcción de la tabla de valores inversos de Z_p*
	var invtab = function() {
		if( /*self::*/_invtab == null ) {
			let x = 1, y = 1 // el inverso de 1 es el 1
			/*self::*/_invtab = []
			for(let i = 0; i < /*self::*/Q; ++i) {
				/*self::*/_invtab[x] = y
				x = /*self::*/modq(3 * x) //el inverso de 3 es 21846 en Z_p*
				y = /*self::*/modq(21846 * y)
			}
		}
		return /*self::*/_invtab
	}

	// Llevar los números a Z_p*
	var modq = function(number) {
		let mod = number % /*self::*/Q
		return (mod < 0) ? mod + /*self::*/Q : mod
	}

	// Retornar el inverso de un número
	var inv = function(i) {
		let $invtab = /*self::*/invtab()//la tabla de inversos cacheada
		return (i < 0) ? /*self::*/modq(-$invtab[-i]) : $invtab[i]
	}

	// Método de Horner para evaluar polinomios
	var horner = function(x, coeffs) {
		let val = 0
		for(const c of coeffs)
			val = /*self::*/modq(x * val + c)
		return val
	}

	// ¿Cuál es el grado del polinomio?
	// El grado debería se quorum - 1, para que pueda ser generado con quorum partes.
	// Acá se genera quorum - 1 coeffs, pero falta el coeffs de mayor grado, que vendría hacer el byte per secret.
	// Revisar thresh():line 2
	var coeffs = function(quorum) {
		$coeffs = []
		for(let i = 0; i < quorum - 1; ++i) {
			$coeffs.push( /*self::*/modq( Math.floor(Math.random() * 65535) ) )
		}
		return $coeffs
	}

	// Interpolación de Lagrange para encontrar los coeffs del polinomio.
	var rcoeffs = function(key_x, quorum) {
		let coeffs = []

		for(let i = 0; i < quorum; ++i) {
			let temp = 1
			for(let j = 0; j < quorum; ++j) {
				if(i != j){
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

	// @result retorna las evaluaciones de {1, 2, 3, ..., number} en el
	// polinomio, cuyos coeffs son {random1, random2,..., byte for secret},  con el método horner
	var thresh = function(byte, number, quorum){
		coeffis = /*self::*/coeffs(quorum)
		coeffis.push( byte ) // cada byte crudo del secreto se convierte en un coeficiente del polinomio

		let result = []
		for(let i = 0; i < number; ++i)	{
			result.push(horner(i + 1, coeffis))
		}
		return result
	}

	//https://stackoverflow.com/a/68545179
	this.dataToUint16Array = async function(data) {
		if(data instanceof Blob) {
			const arrayBuffer = await data.arrayBuffer()
			return new Uint16Array(arrayBuffer)
		}
		const encoder = new TextEncoder()
		return encoder.encode(data)
	}

	this.hash = async (msgUint16) => { // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest#converting_a_digest_to_a_hex_string
		const hashBuffer = await crypto.subtle.digest("SHA-256", msgUint16)
		const hashArray = Array.from(new Uint16Array(hashBuffer))
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
		// Para cualquier otro caso, al menos hay dos partes iguales.
		// Totalmente inseguro.
		if(number > /*self::*/Q - 1 || number < 0) {
			throw new Error(
				"Forfex.share(): number ($number) needs to be between 0 and " +
				(/*self::*/Q - 1) + "."
			)
		}

		if(quorum == null){
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

		for(byte of secret/*message*/){
			//~ console.log(byte)
			for(const $sub_result of /*self::*/thresh(byte, number, quorum) ) {
				//~ console.log($sub_result)
				result.push( $sub_result )
			}
		}
		const len = secret.length

		let keys = []

		//~ //Saving in hexadecimal
		for(let i = 0; i < number; ++i) {
			const len2 = len + 2
			let key = new Uint16Array(len2)
			key[0] = quorum
			key[1] = i + 1

			for(let j = 2, $j = 0; j < key.length; ++j) {
				key[j] = result[$j * number + i]
				//~ key[j] = (t == 256) ? 0 : t // t = 256 entonces t se transforma en una raíz
				++$j
			}
			keys.push(key)
		}

		return keys
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
				key_y.push( key[i] )
			}
		}

		keylen -= 2

		let coeffs = /*self::*/rcoeffs(key_x, quorum)

		let secret = new Uint16Array(keylen)
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
