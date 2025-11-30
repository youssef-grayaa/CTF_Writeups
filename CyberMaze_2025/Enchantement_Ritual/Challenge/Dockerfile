FROM pwn.red/jail

# Copy only the binary and files you need
COPY vuln /srv/app/run
COPY ld-linux-x86-64.so.2 /srv/app/ld-linux-x86-64.so.2
COPY libc.so.6 /srv/app/libc.so.6 


RUN chmod +x /srv/app/ld-linux-x86-64.so.2
RUN chmod +x /srv/app/libc.so.6 



COPY flag.txt /srv/app/flag.txt
RUN chmod 444 /srv/app/flag.txt

