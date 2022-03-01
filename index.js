const crypto = require('crypto')

const password = 'my password'

const SALT_LENGTH = 16
const IV_LENGTH = 16
const PBKDF_ITERATIONS = 100_000_000
const KEY_LENGTH = 256 / 8
const PBKDF_ALGORITHM = 'sha256'
const CYPHER_ALGORITHM = 'aes-256-cbc'

function encrypt(secret) {
  const salt = crypto.randomBytes(SALT_LENGTH)
  const iv = crypto.randomBytes(IV_LENGTH)
  const key = crypto.pbkdf2Sync(
    password,
    salt,
    PBKDF_ITERATIONS,
    KEY_LENGTH,
    PBKDF_ALGORITHM,
  )
  const cipher = crypto.createCipheriv(CYPHER_ALGORITHM, key, iv)
  cipher.write(secret)
  cipher.end()
  const encryptedSecret = cipher.read()
  const output = Buffer.concat([salt, iv, encryptedSecret])

  console.log({
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    encryptedSecret: encryptedSecret.toString('base64'),
    output: output.toString('base64'),
  })

  return output.toString('base64')
}

function decrypt(inputText) {
  const input = Buffer.from(inputText, 'base64')
  const salt = input.slice(0, SALT_LENGTH)
  const iv = input.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH)
  const key = crypto.pbkdf2Sync(
    password,
    salt,
    PBKDF_ITERATIONS,
    KEY_LENGTH,
    PBKDF_ALGORITHM,
  )
  const decipher = crypto.createDecipheriv(CYPHER_ALGORITHM, key, iv)
  decipher.write(input.slice(SALT_LENGTH + IV_LENGTH))
  decipher.end()
  const decryptedSecret = decipher.read()

  console.log(decryptedSecret.toString())
}

// encrypt('')
// decrypt('')
decrypt(encrypt('super secret message'))
