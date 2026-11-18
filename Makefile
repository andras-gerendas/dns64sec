SHELL = /bin/sh
CXX = g++
LIBS = -lpthread -lssl -lcrypto
EXE = dns64sec
TEST_EXE = utest
INC_DIR = include
CXXFLAGS = -O0 -Wall -Werror -Wextra -pedantic -std=c++17 -I$(INC_DIR)

TARGET = $(EXE)
SOURCES = $(shell echo src/*.cc)
TEST_SOURCES = $(shell echo test/*.cc)
HEADERS = $(shell echo $(INC_DIR)/*.h)
OBJECTS = $(SOURCES:.cc=.o)
OBJECTS_WO_MAIN = $(filter-out src/main.o,$(OBJECTS))
TEST_OBJECTS = $(TEST_SOURCES:.cc=.o)

all: $(TARGET)

clean: clean-coverage
	rm -f $(OBJECTS) $(TEST_OBJECTS) $(TARGET) $(TEST_EXE) $(shell echo src/*.gcno) $(shell echo test/*.gcno)

clean-coverage:
	rm -f $(shell echo src/*.gcda) $(shell echo src/*.gcov) $(shell echo coverage.*) $(shell echo test/*.gcda) $(shell echo test/*.gcov) $(shell echo *.gcov)

coverage-build: CXXFLAGS+=-g --coverage

coverage-build: $(TARGET) $(TEST_EXE)

coverage:
	gcovr --exclude "include/NsBuilder.h" --exclude "include/RRBuilder.h" --exclude "include/RRSigBuilder.h" --exclude "include/DnskeyBuilder.h" --exclude "test/.*" --exclude "include/doctest.h" --exclude "include/doctest/trompeloeil.hpp" --exclude "include/trompeloeil/.*" --root . --html-details -o coverage.html

debug: CXXFLAGS+=-g

debug: $(TARGET) $(TEST_EXE)

astyle:
	astyle -C -S -f $(SOURCES) $(HEADERS)

tidy:
	clang-tidy $(SOURCES) -header-filter=.* -checks='*',-llvm-*,-llvmlibc-*,-fuchsia-*,-altera-*,-hicpp-vararg,-cppcoreguidelines-pro-type-vararg,-hicpp-avoid-c-arrays,-modernize-avoid-c-arrays,-cppcoreguidelines-avoid-c-arrays,-cppcoreguidelines-pro-type-reinterpret-cast -extra-arg=-std=c++17 -extra-arg=-I$(INC_DIR)

$(TEST_EXE): $(TEST_OBJECTS) $(OBJECTS_WO_MAIN)
	$(CXX) $(CXXFLAGS) -Wl,--wrap=close,--wrap=ioctl,--wrap=recv,--wrap=sendto,--wrap=setsockopt,--wrap=socket,--wrap=time,--wrap=timerfd_settime -o $(TEST_EXE) $(OBJECTS_WO_MAIN) $(TEST_OBJECTS) $(LIBS)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)