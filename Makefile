CXX = g++

SOURCES_PART1 = part1.cpp
SOURCES_PART2 = part2.cpp
OUTPUT_PART1 = part1
OUTPUT_PART2 = part2

$(OUTPUT_PART1): $(SOURCES_PART1)
	$(CXX) -o $(OUTPUT_PART1) $(SOURCES_PART1) -lssl -lcrypto

$(OUTPUT_PART2): $(SOURCES_PART2)
	$(CXX) -o $(OUTPUT_PART2) $(SOURCES_PART2) -lssl -lcrypto

run_part1: $(OUTPUT_PART1)
	./$(OUTPUT_PART1)

run_part2: $(OUTPUT_PART2)
	./$(OUTPUT_PART2)

clean:
	rm -f $(OUTPUT_PART1) $(OUTPUT_PART2)

all: $(OUTPUT_PART1) $(OUTPUT_PART2)