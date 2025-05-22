# Caso de uso de CBMC para romper un cifrado

## Objetivo

En esta sección se hablará acerca del caso de uso realizado por nuestro equipo para mostrar el posible uso de CBMC en escenarios fuera de lo común, fuera del objetivo para el que fue diseñado.
Esta decisión fue tomada con el objetivo de poder hacer visible la gran flexibilidad que tiene esta herramienta para todo tipo de usos y en todo tipo de contexto: académico, industrial e incluso competitivo.
En base a esta idea, se eligió usar CBMC para romper un cifrado custom creado para un Capture The Flag hecho en 2021: _picoMini_.
El challenge a resolver es [_XtraORdinary_](https://play.picoctf.org/practice/challenge/208) que, si bien nos pareció bastante sencillo, está catalogado como un ejercicio difícil y que resolvieron solo $1655$ personas.

## Descripción del challenge

El challenge no posee ningún tipo de hint y su descripción es la siguiente:

> Check out my new, never-before-seen method of encryption!
> I totally invented it myself.
> I added so many for loops that I don't even know what it does.
> It's extraordinarily secure!

Acompañado de dos archivos adjuntos:

- [encrypt.py](./chall_files/encrypt.py)
- [output.txt](./chall_files/output.txt)

## Análisis del challenge

En base al enunciado y los archivos que están adjuntos, es sencillo notar que se trata de romper un cifrado custom.
Nuestra tarea va a ser romperlo pero usando CBMC para ello.
Por este motivo, al estar implementado este cifrado en python, una primera observación es la necesidad de traducirlo a C o C++ para que estemos habilitados a usar la herramienta que aquí nos convoca.

Otro aspecto a analizar es el código en sí mismo.
Lo primero que hace es leer la flag y la key (valores desconocidos por nosotros) y definir la siguiente función de encriptación:

```python
def encrypt(ptxt, key):
    ctxt = b''
    for i in range(len(ptxt)):
        a = ptxt[i]
        b = key[i % len(key)]
        ctxt += bytes([a ^ b])
    return ctxt
```

la cual es correspondiente a un cifrado XOR con clave repetida.
Es decir, se repite la clave varias veces hasta tener el mismo tamaño de la palabra, y luego se hace XOR entre ambas para obtener el mensaje encriptado.
Notar que, en este caso, esto significa que el algoritmo de desencriptación es exactamente el mismo que el de encriptación porque aplicar dos veces el XOR de lo mismo lo anula.

Luego, si seguimos analizando la implementación, lo que hace es encriptar la flag varias veces con distintas palabras:

```python
ctxt = encrypt(flag, key)

random_strs = [
    b'my encryption method',
    b'is absolutely impenetrable',
    b'and you will never',
    b'ever',
    b'ever',
    b'ever',
    b'ever',
    b'ever',
    b'ever',
    b'break it'
]

for random_str in random_strs:
    for i in range(randint(0, pow(2, 8))):
        for j in range(randint(0, pow(2, 6))):
            for k in range(randint(0, pow(2, 4))):
                for l in range(randint(0, pow(2, 2))):
                    for m in range(randint(0, pow(2, 0))):
                        ctxt = encrypt(ctxt, random_str)
```

Por lo mismo que dijimos anteriormente, si se aplica dos veces el XOR, entonces se anula la encriptación.
Luego, lo anterior se puede simplificar a:

```python
ctxt = encrypt(flag, key)

random_strs = [
    b'my encryption method',
    b'is absolutely impenetrable',
    b'and you will never',
    b'ever',
    b'break it'
]

for random_str in random_strs:
    if(randint(0, 1)):
        ctxt = encrypt(ctxt, random_str)
```

Finalmente, entonces, se imprime el valor encriptado (en formato hexadecimal) que es lo que tenemos en [`output.txt`](./chall_files/output.txt):

```txt
57657535570c1e1c612b3468106a18492140662d2f5967442a2960684d28017931617b1f3637
```

## Solución propuesta con CBMC

La solución que se propone con CBMC es implementar el mismo cifrado (con la reducción en iteraciones a un solo condicional) para que este mismo busque las entradas (flag y key) que generan una encriptación igual a la obtenida al final.

Para este punto, tenemos que notar primero que:

- La longitud de la flag se mantiene durante toda la encriptación, por lo que es la mitad de la longitud del string hexadecimal (es decir, $38$).
- Asumo que la longitud de la clave está entre 1 y la longitud de la flag porque sino no tendría sentido usar este tipo de cifrado (directamente usá one time pad).
- La flag comienza con "picoCTF{" y terminal con "}" debido al formato propio de la bandera.
- Asumo que tanto la flag como la clave tienen caracteres imprimibles en ASCII.

En base a ello, se puede implementar en CBMC el modelo del cifrado del siguiente modo.
La primer parte será la correspondiente a la declaración de tanto la clave como la flag con las correspondientes asunciones mencionadas (para ello se usa el contrato \_\_CPROVER_assume() de CBMC):

```cpp
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

```

Doy la posibilidad de dar la longitud de la clave con una variable de entorno para facilitar la búsqueda debido a que CBMC devuelve una sola traza de error y pueden existir varios pares (flag, key) que den el mismo cifrado.

Posteriormente, se implementa el cifrado con la reducción de los loops en un condicional:

```cpp
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
```

Y, como parte final, se compara la palabra obtenida con el valor hexadecimal que nos dieron como parte del challenge:

```cpp
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
```

Notar que se busca que la aserción de que el cifrado es el incorrecto falle, de modo que CBMC nos otorgue la traza de error con los estados que generan que la comparación se verifique (i.e., el par correcto).

Una vez hecho esto, para facilitar la búsqueda de los distintos pares de trazas usamos un [script de python](./solver.py) que realiza el análisis para cada longitud posible entre 1 y 38 (se puede hacer manualmente también); y que nos imprime los valores posibles de flags para cada tamaño de clave considerada.
Para que CBMC nos devuelva la traza de error, pasemos la longitud de la clave a considerar y establezcamos un límite de desenrollo de loops (para hacer más rápido el análisis), el comando tiene la siguiente estructura:

```sh
cbmc --unwind 100 -DKEY_LENGTH_FIXED={key_length} --trace {cbmc_file}
```

Este mismo mostrará en consola los resultados obtenidos y, en caso de error, mostrará también la traza que lo genera.

Con todo ello, finalmente, se obtienen las siguientes posibles banderas (en solo $6.45$ segundos):

```txt
Flag found with key length 7: picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}
Flag found with key length 14: picoCTF{d0duI00]5Vi `p#\jjlz:kT`=.:;8}
Flag found with key length 21: picoCTF{6"jp`"\V`pc"`?|Y%d ,fdA% G8L>}
Flag found with key length 23: picoCTF{S2>ek&YU`Xf pP2n5}rjVaxK%1d0d}
Flag found with key length 26: picoCTF{&ml p`@R`Pd (XhH1`QcS>L yP.Bc}
Flag found with key length 27: picoCTF{7$|d`dAP$pf bXjAm``GC6[zc:YL1}
Flag found with key length 28: picoCTF{qb0`Dd8B bd pP%Hh``k39Xu4|6.$}
Flag found with key length 35: picoCTF{  pVZ`@Q!T@p$d H8DQ2b2`1p@R??}
```

Luego, la bandera original es: `picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}`.
