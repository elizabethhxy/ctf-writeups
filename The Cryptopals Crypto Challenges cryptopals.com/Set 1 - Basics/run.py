from libmatasano import html_test
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode

# Challenge 1 - Convert hex to base64
hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
b64_string = b64encode(unhexlify(hex_string))
html_test(b64_string == b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')

# Challenge 2 - Fixed XOR
bin(123), bin(127), bin(123 ^ 127)
def bxor(a, b): return bytes([ x^y for (x,y) in zip(a, b)])
A = unhexlify('1c0111001f010100061a024b53535009181c')
B = unhexlify('686974207468652062756c6c277320657965')
expected_result = unhexlify('746865206b696420646f6e277420706c6179')
html_test(bxor(A,B) == expected_result)

# Challenge 3 - Single-byte XOR cipher
msg = b'hi there!'
key = b'\x77'
keystream = key*len(msg)
bxor(msg, keystream)
ciphertext = unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
candidate_key = bytes([1])
keystream = candidate_key*len(ciphertext)
bxor(ciphertext, keystream)
(b'lol').isalpha()
(b'how are you?').isalpha()
ord('a'), ord('b'), ord('z')
ord(' ')
ascii_text_chars = list(range(97, 122)) + [32]
[ x in ascii_text_chars for x in b'how are you?']
sum([ x in ascii_text_chars for x in b'how are you?'])
def letter_ratio(input_bytes):
  nb_letters = sum([ x in ascii_text_chars for x in input_bytes])
  return nb_letters / len(input_bytes)
def is_probably_text(input_bytes):
  r = letter_ratio(input_bytes)
  return True if r>0.7 else False
is_probably_text(b'Hello, how are you?')
is_probably_text(b'\x1e22643:}\x10\x1ez.}1468}<}-2(39}2;}?<>23')
def attack_single_byte_xor(ciphertext):
  best = None
  for i in range(2**8): # for every possible key
    candidate_key = i.to_bytes(1, byteorder='big')
    keystream = candidate_key*len(ciphertext)
    candidate_message = bxor(ciphertext, keystream)
    nb_letters = sum([ x in ascii_text_chars for x in candidate_message])
    if best == None or nb_letters > best['nb_letters']:
      best = {"message": candidate_message, 'nb_letters': nb_letters, 'key': candidate_key}
  return best
result = attack_single_byte_xor(ciphertext)
print('key:', result['key'])
print('message:', result['message'])
print('nb of letters:', result['nb_letters'])
html_test(is_probably_text(result['message']))

# Challenge 4 - Detect single-character XOR
class InvalidMessageException(Exception): pass
def attack_single_byte_xor(ciphertext):
  best = {"nb_letters": 0}
  for i in range(2**8):
    candidate_key = i.to_bytes(1, byteorder='big')
    candidate_message = bxor(ciphertext, candidate_key*len(ciphertext))
    nb_letters = sum([ x in ascii_text_chars for x in candidate_message])
    if nb_letters>best['nb_letters']:
      best = {"message": candidate_message, 'nb_letters': nb_letters, 'key': candidate_key}
  if best['nb_letters'] > 0.7*len(ciphertext):
    return best
  else:
    raise InvalidMessageException('best candidate message is: %s' % best['message'])
from os import urandom
try: attack_single_byte_xor(urandom(16))
except InvalidMessageException:
  print('Got an InvalidMessageException as expected')
else: print('No exception: something is wrong')
with open('data/04.txt') as data_file:
  ciphertext_list = [
    unhexlify(line.strip())
    for line in data_file
  ]
candidates = list()
for (line_nb, ciphertext) in enumerate(ciphertext_list):
  try:
    message = attack_single_byte_xor(ciphertext)['message']
  except InvalidMessageException: pass
  else:
    candidates.append({
      'line_nb': line_nb,
      'ciphertext': ciphertext,
      'message': message
    })
if len(candidates) > 1:
  print("Error: more than one candidate")
  html_test(false)
else:
  for (key, value) in candidates[0].items():
    print(f'{key}: {value}')
  html_test(is_probably_text(candidates[0]['message']))

# Challenge 5 - Implement repeating-key XOR
message = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = b'ICE'
keystream = key*(len(message)//len(key) + 1)
ciphertext = bxor(message, keystream)
expected_result = unhexlify(
	b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d6'
	b'3343c2a26226324272765272a282b2f20430a652e2c652a3124'
	b'333a653e2b2027630c692b20283165286326302e27282f'
)
html_test(ciphertext == expected_result)

# Challenge 6 - Break repeating-key XOR
def hamming_distance(a, b): return sum(bin(byte).count('1') for byte in bxor(a,b))
with open("data/06.txt") as file: ciphertext = b64decode(file.read())
def score_vigenere_key_size(candidate_key_size, ciphertext):
  slice_size = 2*candidate_key_size
  nb_measurements = len(ciphertext) // slice_size - 1
  score = 0
  for i in range(nb_measurements):
    s = slice_size
    k = candidate_key_size
    slice_1 = slice(i*s, i*s + k)
    slice_2 = slice(i*s + k, i*s + 2*k)
    score += hamming_distance(ciphertext[slice_1], ciphertext[slice_2])
  score /= candidate_key_size
  score /= nb_measurements
  return score
def find_vigenere_key_length(ciphertext, min_length=2, max_length=30):
  key = lambda x: score_vigenere_key_size(x,ciphertext)
  return min(range(min_length, max_length), key=key)
def attack_repeating_key_xor(ciphertext):
  keysize = find_vigenere_key_length(ciphertext)
  key = bytes()
  message_parts = list()
  for i in range(keysize):
    part = attack_single_byte_xor(bytes(ciphertext[i::keysize]))
    key += part["key"]
    message_parts.append(part["message"])
  message = bytes()
  for i in range(max(map(len, message_parts))):
    message += bytes([part[i] for part in message_parts if len(part)>=i+1])
  return {'message':message, 'key':key}
result = attack_repeating_key_xor(ciphertext)
print("key:",result["key"],'\n')
print('message:\n')
print(result["message"].decode())

# Challenge 7: AES in ECB mode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()
def decrypt_aes_128_ecb(ctxt, key):
  cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
  decryptor = cipher.decryptor()
  decrypted_data =  decryptor.update(ctxt) + decryptor.finalize()
  message = decrypted_data
  return message
with open("data/07.txt") as file: data = file.read()
print(decrypt_aes_128_ecb(
  ctxt = b64decode(data),
  key=b"YELLOW SUBMARINE"
).decode())

# Challenge 8 - Detect AES in ECB mode
with open('data/08.txt') as f: ctxts = [unhexlify(line.strip()) for line in f]
def has_repeated_blocks(ctxt, blocksize=16):
  if len(ctxt) % blocksize != 0:
    raise Exception('ciphertext length is not a multiple of block size')
  else: num_blocks = len(ctxt) // blocksize
  blocks = [ctxt[i*blocksize:(i+1)*blocksize] for i in range(num_blocks)]
  return len(set(blocks)) != num_blocks
hits = [ctxt for ctxt in ctxts if has_repeated_blocks(ctxt)]
html_test(len(hits)==1)
