/** Known things about the encryption method:
 *
 * 1) Flag length is the half of the length of encrypted string in hex format
 *
 * 2) I assume that key length is between 1 and flag length because in the
 * encryption it use the module for it
 *
 * 3) Flag starts with "picoCTF{" and ends with "}"
 *
 * 4) I assume that flag and key are printable ASCII
 *
 * 5) The encryption method is XOR encryption with repeated key.
 *
 * 6) Notice that isn't important the number of times that we encrypt the flag
 * with the same key because if it's even then isn't encrypted (because we're
 * using XOR). So the only thing to know is if we do it even or odd times.
 **/

#include <cassert>

typedef unsigned char byte;

bool is_printable(byte b) { return (b >= ' ' && b <= '~'); }

int main() {
  // ================ Key and Flag values ================
  const int hex_length = 76;
  const int flag_length = 38; // (hex_length / 2)

#ifdef KEY_LENGTH_FIXED
  // If i give the key length in the command line
  const unsigned int key_length = KEY_LENGTH_FIXED;
#else
  unsigned int key_length; // Unknown value (CBMC will search it)
#endif

  const byte key[key_length];   // Unknown value (CBMC will search it)
  const byte flag[flag_length]; // Unknown value (CBMC will search it)

  // ================ Key and Flag properties ================
  __CPROVER_assume(key_length >= 1 && key_length < flag_length);

  // Flag starts with "picoCTF{" and ends with "}"
  __CPROVER_assume(flag[0] == 'p');
  __CPROVER_assume(flag[1] == 'i');
  __CPROVER_assume(flag[2] == 'c');
  __CPROVER_assume(flag[3] == 'o');
  __CPROVER_assume(flag[4] == 'C');
  __CPROVER_assume(flag[5] == 'T');
  __CPROVER_assume(flag[6] == 'F');
  __CPROVER_assume(flag[7] == '{');
  __CPROVER_assume(flag[37] == '}');

  // Key and flag are both printable ascii
  for (unsigned int i = 0; i < key_length; i++) {
    __CPROVER_assume(is_printable(key[i]));
  }
  for (unsigned int i = 0; i < flag_length; i++) {
    __CPROVER_assume(is_printable(flag[i]));
  }

  // ================ Performing the encryption ================
  // Constant values
  const char *random_strs[5] = {"my encryption method",
                                "is absolutely impenetrable",
                                "and you will never", "ever", "break it"};
  const unsigned int random_strs_length[5] = {20, 26, 18, 4, 8};

  // Encryption method
  byte ctxt[flag_length];
  for (unsigned int i = 0; i < flag_length; i++) {
    ctxt[i] = flag[i] ^ key[i % key_length];
  }

  for (unsigned int i = 0; i < 5; i++) {
    // The quantity of iterations to encrypt isn't important because the only
    // thing to know is if it's even or odd
    bool is_even; // Unknown value (CBMC will search it)
    if (!is_even) {
      for (unsigned int j = 0; j < flag_length; j++) {
        ctxt[j] = ctxt[j] ^ random_strs[i][j % random_strs_length[i]];
      }
    }
  }

  // ================ Check if we found the (flag, key) tuple ================
  // The given hexadecimal encrypted flag
  const byte ciphertext[flag_length] = {
      0x57, 0x65, 0x75, 0x35, 0x57, 0x0c, 0x1e, 0x1c, 0x61, 0x2b,
      0x34, 0x68, 0x10, 0x6a, 0x18, 0x49, 0x21, 0x40, 0x66, 0x2d,
      0x2f, 0x59, 0x67, 0x44, 0x2a, 0x29, 0x60, 0x68, 0x4d, 0x28,
      0x01, 0x79, 0x31, 0x61, 0x7b, 0x1f, 0x36, 0x37};

  // Check if we obtain the same
  bool good = true;
  for (unsigned int i = 0; i < flag_length; i++) {
    if (ctxt[i] != ciphertext[i]) {
      good = false;
      break;
    }
  }

  // To find the trace that has the real flag value
  assert(!good);

  return 0;
}
