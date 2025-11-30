/* vuln_enchant_copyoverflow.c
   Build the expanded output safely, then COPY it all at once into a
   smaller stack buffer (single memcpy) to create a predictable overflow.
   Debug/testing build (CTF only).

   Compile for local testing (sandboxed):
     gcc -g -O0 -fno-stack-protector -no-pie -z execstack -o vuln_enchant_copyoverflow vuln_enchant_copyoverflow.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>



void setup(void){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

const char *map_table[26] = {
    /* a..z map to multi-byte UTF-8 glyphs (examples) */
    "ᔑ","ʖ","ᓵ","↸","ꖎ","ᒷ","ꖌ","ꖎ","ᒲ","ꞁ","ꖌ","リ","ᓭ",
    "ꖇ","ᒲ","⨅","⋮","ꖈ","ꖘ","∴","ᒲ","ꖎ","ꖦ","⨎","ꖫ","╎"
};

const char *map_lookup(char c) {
    if (c >= 'a' && c <= 'z') return map_table[c - 'a'];
    if (c >= 'A' && c <= 'Z') return map_table[c - 'A'];
    static char tmp[2];
    tmp[0] = c;
    tmp[1] = '\0';
    return tmp;
}



void enchant_and_print(void) {
    /* small stack buffer we will overflow on purpose */
    char outbuf[100];                 /* B = 100 */

    char input[100];

    puts("Enter text to enchant (one line):");
    if (!fgets(input, sizeof(input), stdin)) return;
    size_t inlen = strlen(input);
    if (inlen && input[inlen-1] == '\n') { input[--inlen] = '\0'; }

    /* --- 1) compute exact needed size for expanded data --- */
    size_t needed = 1; /* null terminator */
    for (size_t i = 0; i < inlen; ++i) {
        const char *g = map_lookup(input[i]);
        needed += strlen(g);
    }

    /* --- 2) allocate heap buffer and fill it with memcpy (safe) --- */
    char *expanded = malloc(needed);
    if (!expanded) { perror("malloc"); return; }
    char *wp = expanded;
    for (size_t i = 0; i < inlen; ++i) {
        const char *g = map_lookup(input[i]);
        size_t glen = strlen(g);
        memcpy(wp, g, glen);
        wp += glen;
    }
    *wp = '\0';

    /* debug: show first bytes of expanded */

    /* --- 3) intentionally COPY all expanded bytes into small stack buffer WITHOUT checking --- */
    /* This single memcpy is the intentional vulnerability for the challenge. */
    memcpy(outbuf, expanded, needed);   /* if needed > sizeof(outbuf) -> overflow */

    /* --- 4) show results --- */
    printf("enchantment: %s\n",&outbuf);

}


void win(void) {
     printf("||𝙹⚍ ᔑ∷ᒷ ᔑ ∴╎⨅ᔑ∷↸...\n");
	
     char buf[256];
    int fd = open("flag.txt", O_RDONLY);
    if (fd < 0) {
        write(1, "Failed to open flag.txt\n", 24);
        return;
    }

    ssize_t n = read(fd, buf, sizeof(buf));
    if (n > 0) {
        write(1, buf, n);
    }

    close(fd);
}



int main(void) {
    setup();
    enchant_and_print();
    return 0;
}

