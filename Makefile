CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra
INCLUDES = -I includes -I /opt/homebrew/opt/openssl@3/include
LDFLAGS = -L /opt/homebrew/opt/openssl@3/lib
LIBS = -lssl -lcrypto

TARGET = urlvpwn
SOURCES = main.cpp modules/urlvpwn.cpp
OBJECTS = $(SOURCES:.cpp=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) $(LDFLAGS) $(LIBS) -o $(TARGET)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

rebuild: clean all

