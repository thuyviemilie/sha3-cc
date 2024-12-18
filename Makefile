CXX = c++
CXXFLAGS = -std=c++11 -O2 -Wall -Wextra

TARGET = sha3

OBJS = sha3.o utils.o main.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

sha3.o: src/sha3.cpp src/sha3.h
	$(CXX) $(CXXFLAGS) -c src/sha3.cpp

utils.o: src/utils.cpp src/sha3.h
	$(CXX) $(CXXFLAGS) -c src/utils.cpp

main.o: src/main.cpp src/sha3.h
	$(CXX) $(CXXFLAGS) -c src/main.cpp

clean:
	rm -f $(OBJS) $(TARGET)