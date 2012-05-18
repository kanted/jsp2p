CC=				gcc
STD=				_GNU_SOURCE
OBJS=				tcpsg.o
TARGET=			tcpsg
INSTALL_PATH=	/usr/sbin

.c.o:
	$(CC) -c -Wall $(CFLAGS) -D$(STD) $<

all:		$(TARGET)

$(TARGET):	$(OBJS)
	$(CC) $(OBJS) -o $(TARGET)

install: $(TARGET)
	cp -i $(TARGET) $(INSTALL_PATH)
	cp tcpsg.conf /etc/tcpsg.conf 
clean:
	rm -f *.o core

distclean: clean
	rm -f $(TARGET)

uninstall:
	rm -f $(INSTALL_PATH)/$(TARGET)
	rm -f /etc/tcpsg.conf




