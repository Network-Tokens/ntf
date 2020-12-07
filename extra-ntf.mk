CXXFLAGS += -I/opt/ntf/include
LIBS += -Wl,-Bstatic -lcjose -ljansson -lcrypto -L/opt/ntf/api -Wl,--whole-archive -lapi -Wl,--no-whole-archive -Wl,-Bdynamic
