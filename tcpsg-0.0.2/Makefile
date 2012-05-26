CC=		gcc
LD=		gcc
LDFLAGS = 	-lssl -lcrypto
STD=		_GNU_SOURCE
OBJS=		tcpsg.o SSLSocket.o
TARGET=		tcpsg
INSTALL_PATH=	/usr/sbin

.c.o:
	$(CC) -c -Wall $(LDFLAGS) $(CFLAGS) -D$(STD) $<

all:		$(TARGET)

SSLSocket.o: SSLSocket.h

$(TARGET):	$(OBJS)
	$(CC) $(OBJS) -o $(TARGET)

install: $(TARGET)
	cp -i $(TARGET) $(INSTALL_PATH)
	cp tcpsg.conf /usr/local/etc/tcpsg.conf 
clean:
	rm -f *.o core

distclean: clean
	rm -f $(TARGET)

uninstall:
	rm -f $(INSTALL_PATH)/$(TARGET)
	rm -f /usr/local/etc/tcpsg.conf




