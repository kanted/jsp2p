CC=		gcc
LDFLAGS = 	-lssl -lcrypto
STD=		_GNU_SOURCE
OBJS=		tcpsg.o SSLSocket.o
TARGET=		tcpsg
INSTALL_PATH=	/usr/sbin

.c.o:
	$(CC) -c -Wall $(CFLAGS) -D$(STD) $<

all:		$(TARGET)

SSLSocket.o: SSLSocket.h

$(TARGET):	$(OBJS)
	$(CC) -Wall $(OBJS) $(LDFLAGS) -o $(TARGET)

install: $(TARGET)
	cp -i $(TARGET) $(INSTALL_PATH)
	cp tcpsg.conf ${PREFIX}/etc/tcpsg.conf 
clean:
	rm -f *.o core

distclean: clean
	rm -f $(TARGET)

uninstall:
	rm -f $(INSTALL_PATH)/$(TARGET)
	rm -f ${PREFIX}/etc/tcpsg.conf




