INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/
all:
	g++ -I$(INC) -L$(LIB) tunproxy.cpp -o tunproxy -w -lssl -lcrypto -ldl -fpermissive
