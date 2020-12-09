CXXFLAGS += -I/opt/ntf/include
LIBS += -Wl,-Bstatic -lcjose -ljansson -lcrypto -Wl,-Bdynamic
