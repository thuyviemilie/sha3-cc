CXX = c++
CXXFLAGS = -std=c++11 -O2 -Wall -Wextra

TARGET = sha3

OBJS = src/sha3.o src/utils.o src/main.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

src/sha3.o: src/sha3.cc src/sha3.h
	$(CXX) $(CXXFLAGS) -c src/sha3.cc -o src/sha3.o

src/utils.o: src/utils.cc src/sha3.h
	$(CXX) $(CXXFLAGS) -c src/utils.cc -o src/utils.o

src/main.o: src/main.cc src/sha3.h
	$(CXX) $(CXXFLAGS) -c src/main.cc -o src/main.o

test: all
	./test/run_tests.sh

clean:
	rm -f $(OBJS) $(TARGET)
