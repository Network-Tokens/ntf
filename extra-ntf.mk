CXXFLAGS += -I/opt/ntf/include
LIBS += -Wl,--whole-archive -L/opt/ntf/api -lapi -Wl,--no-whole-archive -Wl,-Bstatic -lcjose -ljansson -lcrypto -Wl,-Bdynamic
