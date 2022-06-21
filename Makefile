SHELL = /bin/sh
CXX = g++
LIBS = -lpthread -lssl -lcrypto
EXE = dns64sec
INC_DIR = include
CXXFLAGS = -O2 -Wall -Werror -Wextra -pedantic -std=c++17 -I$(INC_DIR)

TARGET = $(EXE)
SOURCES = $(shell echo src/*.cc)
HEADERS = $(shell echo $(INC_DIR)/*.h)
OBJECTS = $(SOURCES:.cc=.o)

all: $(TARGET)

clean:
	rm -f $(OBJECTS) $(TARGET)

astyle:
	astyle -C -S -f $(SOURCES) $(HEADERS)

tidy:
	clang-tidy $(SOURCES) -header-filter=.* -checks='*',-hicpp-vararg,-cppcoreguidelines-pro-type-vararg,-fuchsia-default-arguments-declarations,-fuchsia-trailing-return,-fuchsia-default-arguments-calls,-hicpp-avoid-c-arrays,-modernize-avoid-c-arrays,-cppcoreguidelines-avoid-c-arrays,-fuchsia-overloaded-operator,-llvm-header-guard,-cppcoreguidelines-pro-type-reinterpret-cast -extra-arg=-std=c++17 -extra-arg=-I$(INC_DIR)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)