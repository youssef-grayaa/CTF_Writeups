// vuln_server.c
// Minimal vulnerable HTTP server for CTF (GET page + POST buffer overflow)

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#define PORT 8080
#define BACKLOG 3

void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

// ---- win(): attacker wants to call this ----
/*
int win(void){
    system("cat flag.txt");
}
*/

void serve_index(int client_fd, void *body_addr) {
    void *puts_addr = (void*)puts;

    char html[4096];
    snprintf(html, sizeof(html),
"<!DOCTYPE html>"
"<html>"
"<head>"
"<title>CYBERMAZE</title>"
"<style>"
"@import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap');"
"body {"
"    margin:0;"
"    padding:0;"
"    font-family: 'Press Start 2P', monospace;"
"    background: #111;"
"    color: #ff4444;"
"    image-rendering: pixelated;"
"    overflow-x: hidden;"
"    animation: flicker 0.15s infinite alternate;"
"}"
".container {"
"    max-width: 700px;"
"    margin: 50px auto;"
"    padding: 30px;"
"    background: rgba(0,0,0,0.85);"
"    border: 4px solid #ff4444;"
"    box-shadow: 0 0 20px #ff4444;"
"    text-align: center;"
"    position: relative;"
"}"
"h1 {"
"    font-size: 22px;"
"    margin-bottom: 20px;"
"    color: #ffcc00;"
"    text-shadow: 0 0 10px #ffcc00;"
"}"
".boss {"
"    font-size: 16px;"
"    color: #ff4444;"
"    text-shadow: 0 0 6px #ff4444;"
"}"
".hint {"
"    font-size: 14px;"
"    margin-top: 20px;"
"    color: #33ff66;"
"    text-shadow: 0 0 8px #33ff66;"
"}"
".health-bar {"
"    width: 100%;"
"    background: #222;"
"    border: 2px solid #ff4444;"
"    margin-top: 10px;"
"    height: 20px;"
"    position: relative;"
"}"
".health {"
"    width: 75%;"
"    height: 100%;"
"    background: #ff4444;"
"}"
"@keyframes flicker {"
"  0% { opacity: 0.95; }"
"  50% { opacity: 1; }"
"  100% { opacity: 0.97; }"
"}"
"</style>"
"</head>"
"<body>"
"<div class='container'>"
"<h1> >_< </h1>"
"<div class='boss'>🔥 Final BOSS 🔥</div>"
"<div class='health-bar'><div class='health'></div></div>"
"<p class='hint'>SEND WHATEVER YOU WANT i know you can't defeat me...</p>"
"<p style='margin-top:20px;'>Stack Leak (body buffer addr): %p</p>"
"<p style='margin-top:20px;'>Maybe This Helps... %p</p>"
"</div>"
"</body></html>",
body_addr, puts_addr
    );



    char header[256];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: text/html\r\n"
             "Content-Length: %zu\r\n"
             "\r\n",
             strlen(html));

    write(client_fd, header, strlen(header));
    write(client_fd, html, strlen(html));
}

// ---- Vulnerable POST /submit ----
void handle_submit(int client_fd, const char *body) {
    char buf[80];  // overflow target

    // Vulnerability: no bounds check 24-byte overflow
    memcpy(buf, body, 128);

    const char *resp_header =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n\r\n";
    write(client_fd, resp_header, strlen(resp_header));

    write(client_fd, "Received: ", 10);
    write(client_fd, buf, strlen(buf));
}

// ---- Helper: read exactly n bytes ----
ssize_t read_n(int fd, void *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = read(fd, (char*)buf + total, n - total);
        if (r <= 0) return total; // EOF or error
        total += r;
    }
    return total;
}

void handle_client(int client_fd) {
    char req[4096];
    ssize_t n = read(client_fd, req, sizeof(req)-1);
    if (n <= 0) { close(client_fd); return; }
    req[n] = '\0';

    char method[8], path[64];
    sscanf(req, "%7s %63s", method, path);

    dup2(client_fd, 1);
    dup2(client_fd, 2);

    // stack buffer for POST body
    char body[4096];

    // GET /
    if (strcmp(method, "GET") == 0 && strcmp(path, "/") == 0) {
        serve_index(client_fd, body);
        close(client_fd);
        return;
    }

    // POST /submit
    if (strcmp(method, "POST") == 0 && strcmp(path, "/submit") == 0) {
        char *body_start = strstr(req, "\r\n\r\n");
        if (body_start) body_start += 4;
        else body_start = "";

        // check for Content-Length header
        size_t content_len = 0;
        char *cl = strcasestr(req, "Content-Length:");
        if (cl) {
            cl += 15; // skip header
            content_len = strtoul(cl, NULL, 10);
            if (content_len > sizeof(body)) content_len = sizeof(body);
        }

        size_t already_read = n - (body_start - req);
        if (already_read > content_len) already_read = content_len;

        memcpy(body, body_start, already_read);

        // read remaining bytes if needed
        if (already_read < content_len) {
            read_n(client_fd, body + already_read, content_len - already_read);
        }

        handle_submit(client_fd, body);
        close(client_fd);
        return;
    }

    const char *resp =
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Length: 9\r\n\r\nNot Found";
    write(client_fd, resp, strlen(resp));
    close(client_fd);
}

int main() {
    setup();

    int sock, client;
    struct sockaddr_in addr;
    socklen_t slen = sizeof(addr);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); exit(1); }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); exit(1); }
    if (listen(sock, BACKLOG) < 0) { perror("listen"); exit(1); }

    printf("Listening on port %d\n", PORT);

    while (1) {
        client = accept(sock, (struct sockaddr*)&addr, &slen);
        if (client < 0) { perror("accept"); continue; }
        handle_client(client);
    }
}

